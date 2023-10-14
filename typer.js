var escapedSource = 'static void put_ctx(struct context *ctx)\n{\n	if (atomic_dec_and_test(&ctx->ref))\n		complete(&ctx->comp);\n}\n\nstatic struct context *alloc_ctx(struct file *file)\n{\n	struct context *ctx;\n\n	ctx = alloc(sizeof(*ctx), GFP_KERNEL);\n	if (!ctx)\n		return NULL;\n\n	atomic_set(&ctx->ref, 1);\n	init_completion(&ctx->comp);\n	INIT_LIST_HEAD(&ctx->mc_list);\n	ctx->file = file;\n\n	mutex_lock(&mut);\n	ctx->id = idr_alloc(&ctx_idr, ctx, 0, 0, GFP_KERNEL);\n	mutex_unlock(&mut);\n	if (ctx->id < 0)\n		goto error;\n\n	list_add_tail(&ctx->list, &file->ctx_list);\n	return ctx;\n\nerror:\n	kfree(ctx);\n	return NULL;\n}\n\nstatic struct multicast* alloc_multicast(struct context *ctx)\n{\n	struct multicast *mc;\n\n	mc = alloc(sizeof(*mc), GFP_KERNEL);\n	if (!mc)\n		return NULL;\n\n	mutex_lock(&mut);\n	mc->id = idr_alloc(&multicast_idr, mc, 0, 0, GFP_KERNEL);\n	mutex_unlock(&mut);\n	if (mc->id < 0)\n		goto error;\n\n	mc->ctx = ctx;\n	list_add_tail(&mc->list, &ctx->mc_list);\n	return mc;\n\nerror:\n	kfree(mc);\n	return NULL;\n}\n\nstatic void copy_conn_event(struct rdma_ucm_conn_param *dst,\n				 struct rdma_conn_param *src)\n{\n	if (src->private_data_len)\n		memcpy(dst->private_data, src->private_data,\n		       src->private_data_len);\n	dst->private_data_len = src->private_data_len;\n	dst->responder_resources = src->responder_resources;\n	dst->initiator_depth = src->initiator_depth;\n	dst->flow_control = src->flow_control;\n	dst->retry_count = src->retry_count;\n	dst->rnr_retry_count = src->rnr_retry_count;\n	dst->srq = src->srq;\n	dst->qp_num = src->qp_num;\n}\n\nstatic void copy_ud_event(struct rdma_ucm_ud_param *dst,\n			       struct rdma_ud_param *src)\n{\n	if (src->private_data_len)\n		memcpy(dst->private_data, src->private_data,\n		       src->private_data_len);\n	dst->private_data_len = src->private_data_len;\n	ib_copy_ah_attr_to_user(&dst->ah_attr, &src->ah_attr);\n	dst->qp_num = src->qp_num;\n	dst->qkey = src->qkey;\n}\n\nstatic void set_event_context(struct context *ctx,\n				   struct rdma_cm_event *event,\n				   struct event *uevent)\n{\n	uevent->ctx = ctx;\n	switch (event->event) {\n	case RDMA_CM_EVENT_MULTICAST_JOIN:\n	case RDMA_CM_EVENT_MULTICAST_ERROR:\n		uevent->mc = (struct multicast *)\n			     event->param.ud.private_data;\n		uevent->resp.uid = uevent->mc->uid;\n		uevent->resp.id = uevent->mc->id;\n		break;\n	default:\n		uevent->resp.uid = ctx->uid;\n		uevent->resp.id = ctx->id;\n		break;\n	}\n}\n\nstatic int event_handler(struct rdma_cm_id *cm_id,\n			      struct rdma_cm_event *event)\n{\n	struct event *uevent;\n	struct context *ctx = cm_id->context;\n	int ret = 0;\n\n	uevent = alloc(sizeof(*uevent), GFP_KERNEL);\n	if (!uevent)\n		return event->event == RDMA_CM_EVENT_CONNECT_REQUEST;\n\n	mutex_lock(&ctx->file->mut);\n	uevent->cm_id = cm_id;\n	set_event_context(ctx, event, uevent);\n	uevent->resp.event = event->event;\n	uevent->resp.status = event->status;\n	if (cm_id->qp_type == IB_QPT_UD)\n		copy_ud_event(&uevent->resp.param.ud, &event->param.ud);\n	else\n		copy_conn_event(&uevent->resp.param.conn,\n				     &event->param.conn);\n\n	if (event->event == RDMA_CM_EVENT_CONNECT_REQUEST) {\n		if (!ctx->backlog) {\n			ret = -ENOMEM;\n			kfree(uevent);\n			goto out;\n		}\n		ctx->backlog--;\n	} else if (!ctx->uid || ctx->cm_id != cm_id) {\n		/*\n		 * We ignore events for new connections until userspace has set\n		 * their context.  This can only happen if an error occurs on a\n		 * new connection before the user accepts it.  This is okay,\n		 * since the accept will just fail later.\n		 */\n		kfree(uevent);\n		goto out;\n	}\n\n	list_add_tail(&uevent->list, &ctx->file->event_list);\n	wake_up_interruptible(&ctx->file->poll_wait);\nout:\n	mutex_unlock(&ctx->file->mut);\n	return ret;\n}\n\nstatic ssize_t get_event(struct file *file, const char __user *inbuf,\n			      int in_len, int out_len)\n{\n	struct context *ctx;\n	struct rdma_ucm_get_event cmd;\n	struct event *uevent;\n	int ret = 0;\n\n	if (out_len < sizeof uevent->resp)\n		return -ENOSPC;\n\n	if (copy_from_user(&cmd, inbuf, sizeof(cmd)))\n		return -EFAULT;\n\n	mutex_lock(&file->mut);\n	while (list_empty(&file->event_list)) {\n		mutex_unlock(&file->mut);\n\n		if (file->filp->f_flags & O_NONBLOCK)\n			return -EAGAIN;\n\n		if (wait_event_interruptible(file->poll_wait,\n					     !list_empty(&file->event_list)))\n			return -ERESTARTSYS;\n\n		mutex_lock(&file->mut);\n	}\n\n	uevent = list_entry(file->event_list.next, struct event, list);\n\n	if (uevent->resp.event == RDMA_CM_EVENT_CONNECT_REQUEST) {\n		ctx = alloc_ctx(file);\n		if (!ctx) {\n			ret = -ENOMEM;\n			goto done;\n		}\n		uevent->ctx->backlog++;\n		ctx->cm_id = uevent->cm_id;\n		ctx->cm_id->context = ctx;\n		uevent->resp.id = ctx->id;\n	}\n\n	if (copy_to_user((void __user *)(unsigned long)cmd.response,\n			 &uevent->resp, sizeof uevent->resp)) {\n		ret = -EFAULT;\n		goto done;\n	}\n\n	list_del(&uevent->list);\n	uevent->ctx->events_reported++;\n	if (uevent->mc)\n		uevent->mc->events_reported++;\n	kfree(uevent);\ndone:\n	mutex_unlock(&file->mut);\n	return ret;\n}\n\nstatic int get_qp_type(struct rdma_ucm_create_id *cmd, enum ib_qp_type *qp_type)\n{\n	switch (cmd->ps) {\n	case RDMA_PS_TCP:\n		*qp_type = IB_QPT_RC;\n		return 0;\n	case RDMA_PS_UDP:\n	case RDMA_PS_IPOIB:\n		*qp_type = IB_QPT_UD;\n		return 0;\n	case RDMA_PS_IB:\n		*qp_type = cmd->qp_type;\n		return 0;\n	default:\n		return -EINVAL;\n	}\n}\n\nstatic ssize_t create_id(struct file *file, const char __user *inbuf,\n			      int in_len, int out_len)\n{\n	struct rdma_ucm_create_id cmd;\n	struct rdma_ucm_create_id_resp resp;\n	struct context *ctx;\n	enum ib_qp_type qp_type;\n	int ret;\n\n	if (out_len < sizeof(resp))\n		return -ENOSPC;\n\n	if (copy_from_user(&cmd, inbuf, sizeof(cmd)))\n		return -EFAULT;\n\n	ret = get_qp_type(&cmd, &qp_type);\n	if (ret)\n		return ret;\n\n	mutex_lock(&file->mut);\n	ctx = alloc_ctx(file);\n	mutex_unlock(&file->mut);\n	if (!ctx)\n		return -ENOMEM;\n\n	ctx->uid = cmd.uid;\n	ctx->cm_id = rdma_create_id(event_handler, ctx, cmd.ps, qp_type);\n	if (IS_ERR(ctx->cm_id)) {\n		ret = PTR_ERR(ctx->cm_id);\n		goto err1;\n	}\n\n	resp.id = ctx->id;\n	if (copy_to_user((void __user *)(unsigned long)cmd.response,\n			 &resp, sizeof(resp))) {\n		ret = -EFAULT;\n		goto err2;\n	}\n	return 0;\n\nerr2:\n	rdma_destroy_id(ctx->cm_id);\nerr1:\n	mutex_lock(&mut);\n	idr_remove(&ctx_idr, ctx->id);\n	mutex_unlock(&mut);\n	kfree(ctx);\n	return ret;\n}\n\nstatic void cleanup_multicast(struct context *ctx)\n{\n	struct multicast *mc, *tmp;\n\n	mutex_lock(&mut);\n	list_for_each_entry_safe(mc, tmp, &ctx->mc_list, list) {\n		list_del(&mc->list);\n		idr_remove(&multicast_idr, mc->id);\n		kfree(mc);\n	}\n	mutex_unlock(&mut);\n}\n\nstatic void cleanup_mc_events(struct multicast *mc)\n{\n	struct event *uevent, *tmp;\n\n	list_for_each_entry_safe(uevent, tmp, &mc->ctx->file->event_list, list) {\n		if (uevent->mc != mc)\n			continue;\n\n		list_del(&uevent->list);\n		kfree(uevent);\n	}\n}\n\n/*\n * We cannot hold file->mut when calling rdma_destroy_id() or we can\n * deadlock.  We also acquire file->mut in event_handler(), and\n * rdma_destroy_id() will wait until all callbacks have completed.\n */\nstatic int free_ctx(struct context *ctx)\n{\n	int events_reported;\n	struct event *uevent, *tmp;\n	LIST_HEAD(list);\n\n	/* No new events will be generated after destroying the id. */\n	rdma_destroy_id(ctx->cm_id);\n\n	cleanup_multicast(ctx);\n\n	/* Cleanup events not yet reported to the user. */\n	mutex_lock(&ctx->file->mut);\n	list_for_each_entry_safe(uevent, tmp, &ctx->file->event_list, list) {\n		if (uevent->ctx == ctx)\n			list_move_tail(&uevent->list, &list);\n	}\n	list_del(&ctx->list);\n	mutex_unlock(&ctx->file->mut);\n\n	list_for_each_entry_safe(uevent, tmp, &list, list) {\n		list_del(&uevent->list);\n		if (uevent->resp.event == RDMA_CM_EVENT_CONNECT_REQUEST)\n			rdma_destroy_id(uevent->cm_id);\n		kfree(uevent);\n	}\n\n	events_reported = ctx->events_reported;\n	kfree(ctx);\n	return events_reported;\n}\n\nstatic ssize_t destroy_id(struct file *file, const char __user *inbuf,\n			       int in_len, int out_len)\n{\n	struct rdma_ucm_destroy_id cmd;\n	struct rdma_ucm_destroy_id_resp resp;\n	struct context *ctx;\n	int ret = 0;\n\n	if (out_len < sizeof(resp))\n		return -ENOSPC;\n\n	if (copy_from_user(&cmd, inbuf, sizeof(cmd)))\n		return -EFAULT;\n\n	mutex_lock(&mut);\n	ctx = _find_context(cmd.id, file);\n	if (!IS_ERR(ctx))\n		idr_remove(&ctx_idr, ctx->id);\n	mutex_unlock(&mut);\n\n	if (IS_ERR(ctx))\n		return PTR_ERR(ctx);\n\n	put_ctx(ctx);\n	wait_for_completion(&ctx->comp);\n	resp.events_reported = free_ctx(ctx);\n\n	if (copy_to_user((void __user *)(unsigned long)cmd.response,\n			 &resp, sizeof(resp)))\n		ret = -EFAULT;\n\n	return ret;\n}\n\nstatic ssize_t bind_ip(struct file *file, const char __user *inbuf,\n			      int in_len, int out_len)\n{\n	struct rdma_ucm_bind_ip cmd;\n	struct context *ctx;\n	int ret;\n\n	if (copy_from_user(&cmd, inbuf, sizeof(cmd)))\n		return -EFAULT;\n\n	ctx = get_ctx(file, cmd.id);\n	if (IS_ERR(ctx))\n		return PTR_ERR(ctx);\n\n	ret = rdma_bind_addr(ctx->cm_id, (struct sockaddr *) &cmd.addr);\n	put_ctx(ctx);\n	return ret;\n}\n\nstatic ssize_t bind(struct file *file, const char __user *inbuf,\n			 int in_len, int out_len)\n{\n	struct rdma_ucm_bind cmd;\n	struct sockaddr *addr;\n	struct context *ctx;\n	int ret;\n\n	if (copy_from_user(&cmd, inbuf, sizeof(cmd)))\n		return -EFAULT;\n\n	addr = (struct sockaddr *) &cmd.addr;\n	if (cmd.reserved || !cmd.addr_size || (cmd.addr_size != rdma_addr_size(addr)))\n		return -EINVAL;\n\n	ctx = get_ctx(file, cmd.id);\n	if (IS_ERR(ctx))\n		return PTR_ERR(ctx);\n\n	ret = rdma_bind_addr(ctx->cm_id, addr);\n	put_ctx(ctx);\n	return ret;\n}\n\nstatic ssize_t resolve_ip(struct file *file,\n			       const char __user *inbuf,\n			       int in_len, int out_len)\n{\n	struct rdma_ucm_resolve_ip cmd;\n	struct context *ctx;\n	int ret;\n\n	if (copy_from_user(&cmd, inbuf, sizeof(cmd)))\n		return -EFAULT;\n\n	ctx = get_ctx(file, cmd.id);\n	if (IS_ERR(ctx))\n		return PTR_ERR(ctx);\n\n	ret = rdma_resolve_addr(ctx->cm_id, (struct sockaddr *) &cmd.src_addr,\n				(struct sockaddr *) &cmd.dst_addr,\n				cmd.timeout_ms);\n	put_ctx(ctx);\n	return ret;\n}\n\nstatic ssize_t resolve_addr(struct file *file,\n				 const char __user *inbuf,\n				 int in_len, int out_len)\n{\n	struct rdma_ucm_resolve_addr cmd;\n	struct sockaddr *src, *dst;\n	struct context *ctx;\n	int ret;\n\n	if (copy_from_user(&cmd, inbuf, sizeof(cmd)))\n		return -EFAULT;\n\n	src = (struct sockaddr *) &cmd.src_addr;\n	dst = (struct sockaddr *) &cmd.dst_addr;\n	if (cmd.reserved || (cmd.src_size && (cmd.src_size != rdma_addr_size(src))) ||\n	    !cmd.dst_size || (cmd.dst_size != rdma_addr_size(dst)))\n		return -EINVAL;\n\n	ctx = get_ctx(file, cmd.id);\n	if (IS_ERR(ctx))\n		return PTR_ERR(ctx);\n\n	ret = rdma_resolve_addr(ctx->cm_id, src, dst, cmd.timeout_ms);\n	put_ctx(ctx);\n	return ret;\n}\n\nstatic ssize_t resolve_route(struct file *file,\n				  const char __user *inbuf,\n				  int in_len, int out_len)\n{\n	struct rdma_ucm_resolve_route cmd;\n	struct context *ctx;\n	int ret;\n\n	if (copy_from_user(&cmd, inbuf, sizeof(cmd)))\n		return -EFAULT;\n\n	ctx = get_ctx(file, cmd.id);\n	if (IS_ERR(ctx))\n		return PTR_ERR(ctx);\n\n	ret = rdma_resolve_route(ctx->cm_id, cmd.timeout_ms);\n	put_ctx(ctx);\n	return ret;\n}\n\nstatic void copy_ib_route(struct rdma_ucm_query_route_resp *resp,\n			       struct rdma_route *route)\n{\n	struct rdma_dev_addr *dev_addr;\n\n	resp->num_paths = route->num_paths;\n	switch (route->num_paths) {\n	case 0:\n		dev_addr = &route->addr.dev_addr;\n		rdma_addr_get_dgid(dev_addr,\n				   (union ib_gid *) &resp->ib_route[0].dgid);\n		rdma_addr_get_sgid(dev_addr,\n				   (union ib_gid *) &resp->ib_route[0].sgid);\n		resp->ib_route[0].pkey = cpu_to_be16(ib_addr_get_pkey(dev_addr));\n		break;\n	case 2:\n		ib_copy_path_rec_to_user(&resp->ib_route[1],\n					 &route->path_rec[1]);\n		/* fall through */\n	case 1:\n		ib_copy_path_rec_to_user(&resp->ib_route[0],\n					 &route->path_rec[0]);\n		break;\n	default:\n		break;\n	}\n}\n\nstatic void copy_iboe_route(struct rdma_ucm_query_route_resp *resp,\n				 struct rdma_route *route)\n{\n\n	resp->num_paths = route->num_paths;\n	switch (route->num_paths) {\n	case 0:\n		rdma_ip2gid((struct sockaddr *)&route->addr.dst_addr,\n			    (union ib_gid *)&resp->ib_route[0].dgid);\n		rdma_ip2gid((struct sockaddr *)&route->addr.src_addr,\n			    (union ib_gid *)&resp->ib_route[0].sgid);\n		resp->ib_route[0].pkey = cpu_to_be16(0xffff);\n		break;\n	case 2:\n		ib_copy_path_rec_to_user(&resp->ib_route[1],\n					 &route->path_rec[1]);\n		/* fall through */\n	case 1:\n		ib_copy_path_rec_to_user(&resp->ib_route[0],\n					 &route->path_rec[0]);\n		break;\n	default:\n		break;\n	}\n}\n\nstatic void copy_iw_route(struct rdma_ucm_query_route_resp *resp,\n			       struct rdma_route *route)\n{\n	struct rdma_dev_addr *dev_addr;\n\n	dev_addr = &route->addr.dev_addr;\n	rdma_addr_get_dgid(dev_addr, (union ib_gid *) &resp->ib_route[0].dgid);\n	rdma_addr_get_sgid(dev_addr, (union ib_gid *) &resp->ib_route[0].sgid);\n}\n\nstatic ssize_t query_route(struct file *file,\n				const char __user *inbuf,\n				int in_len, int out_len)\n{\n	struct rdma_ucm_query cmd;\n	struct rdma_ucm_query_route_resp resp;\n	struct context *ctx;\n	struct sockaddr *addr;\n	int ret = 0;\n\n	if (out_len < sizeof(resp))\n		return -ENOSPC;\n\n	if (copy_from_user(&cmd, inbuf, sizeof(cmd)))\n		return -EFAULT;\n\n	ctx = get_ctx(file, cmd.id);\n	if (IS_ERR(ctx))\n		return PTR_ERR(ctx);\n\n	memset(&resp, 0, sizeof resp);\n	addr = (struct sockaddr *) &ctx->cm_id->route.addr.src_addr;\n	memcpy(&resp.src_addr, addr, addr->sa_family == AF_INET ?\n				     sizeof(struct sockaddr_in) :\n				     sizeof(struct sockaddr_in6));\n	addr = (struct sockaddr *) &ctx->cm_id->route.addr.dst_addr;\n	memcpy(&resp.dst_addr, addr, addr->sa_family == AF_INET ?\n				     sizeof(struct sockaddr_in) :\n				     sizeof(struct sockaddr_in6));\n	if (!ctx->cm_id->device)\n		goto out;\n\n	resp.node_guid = (__force __u64) ctx->cm_id->device->node_guid;\n	resp.port_num = ctx->cm_id->port_num;\n	switch (rdma_node_get_transport(ctx->cm_id->device->node_type)) {\n	case RDMA_TRANSPORT_IB:\n		switch (rdma_port_get_link_layer(ctx->cm_id->device,\n			ctx->cm_id->port_num)) {\n		case IB_LINK_LAYER_INFINIBAND:\n			copy_ib_route(&resp, &ctx->cm_id->route);\n			break;\n		case IB_LINK_LAYER_ETHERNET:\n			copy_iboe_route(&resp, &ctx->cm_id->route);\n			break;\n		default:\n			break;\n		}\n		break;\n	case RDMA_TRANSPORT_IWARP:\n		copy_iw_route(&resp, &ctx->cm_id->route);\n		break;\n	default:\n		break;\n	}\n\nout:\n	if (copy_to_user((void __user *)(unsigned long)cmd.response,\n			 &resp, sizeof(resp)))\n		ret = -EFAULT;\n\n	put_ctx(ctx);\n	return ret;\n}\n\nstatic void query_device_addr(struct rdma_cm_id *cm_id,\n				   struct rdma_ucm_query_addr_resp *resp)\n{\n	if (!cm_id->device)\n		return;\n\n	resp->node_guid = (__force __u64) cm_id->device->node_guid;\n	resp->port_num = cm_id->port_num;\n	resp->pkey = (__force __u16) cpu_to_be16(\n		     ib_addr_get_pkey(&cm_id->route.addr.dev_addr));\n}\n\nstatic ssize_t query_addr(struct context *ctx,\n			       void __user *response, int out_len)\n{\n	struct rdma_ucm_query_addr_resp resp;\n	struct sockaddr *addr;\n	int ret = 0;\n\n	if (out_len < sizeof(resp))\n		return -ENOSPC;\n\n	memset(&resp, 0, sizeof resp);\n\n	addr = (struct sockaddr *) &ctx->cm_id->route.addr.src_addr;\n	resp.src_size = rdma_addr_size(addr);\n	memcpy(&resp.src_addr, addr, resp.src_size);\n\n	addr = (struct sockaddr *) &ctx->cm_id->route.addr.dst_addr;\n	resp.dst_size = rdma_addr_size(addr);\n	memcpy(&resp.dst_addr, addr, resp.dst_size);\n\n	query_device_addr(ctx->cm_id, &resp);\n\n	if (copy_to_user(response, &resp, sizeof(resp)))\n		ret = -EFAULT;\n\n	return ret;\n}\n\nstatic ssize_t query_path(struct context *ctx,\n			       void __user *response, int out_len)\n{\n	struct rdma_ucm_query_path_resp *resp;\n	int i, ret = 0;\n\n	if (out_len < sizeof(*resp))\n		return -ENOSPC;\n\n	resp = alloc(out_len, GFP_KERNEL);\n	if (!resp)\n		return -ENOMEM;\n\n	resp->num_paths = ctx->cm_id->route.num_paths;\n	for (i = 0, out_len -= sizeof(*resp);\n	     i < resp->num_paths && out_len > sizeof(struct ib_path_rec_data);\n	     i++, out_len -= sizeof(struct ib_path_rec_data)) {\n\n		resp->path_data[i].flags = IB_PATH_GMP | IB_PATH_PRIMARY |\n					   IB_PATH_BIDIRECTIONAL;\n		ib_sa_pack_path(&ctx->cm_id->route.path_rec[i],\n				&resp->path_data[i].path_rec);\n	}\n\n	if (copy_to_user(response, resp,\n			 sizeof(*resp) + (i * sizeof(struct ib_path_rec_data))))\n		ret = -EFAULT;\n\n	kfree(resp);\n	return ret;\n}\n\nstatic ssize_t query_gid(struct context *ctx,\n			      void __user *response, int out_len)\n{\n	struct rdma_ucm_query_addr_resp resp;\n	struct sockaddr_ib *addr;\n	int ret = 0;\n\n	if (out_len < sizeof(resp))\n		return -ENOSPC;\n\n	memset(&resp, 0, sizeof resp);\n\n	query_device_addr(ctx->cm_id, &resp);\n\n	addr = (struct sockaddr_ib *) &resp.src_addr;\n	resp.src_size = sizeof(*addr);\n	if (ctx->cm_id->route.addr.src_addr.ss_family == AF_IB) {\n		memcpy(addr, &ctx->cm_id->route.addr.src_addr, resp.src_size);\n	} else {\n		addr->sib_family = AF_IB;\n		addr->sib_pkey = (__force __be16) resp.pkey;\n		rdma_addr_get_sgid(&ctx->cm_id->route.addr.dev_addr,\n				   (union ib_gid *) &addr->sib_addr);\n		addr->sib_sid = rdma_get_service_id(ctx->cm_id, (struct sockaddr *)\n						    &ctx->cm_id->route.addr.src_addr);\n	}\n\n	addr = (struct sockaddr_ib *) &resp.dst_addr;\n	resp.dst_size = sizeof(*addr);\n	if (ctx->cm_id->route.addr.dst_addr.ss_family == AF_IB) {\n		memcpy(addr, &ctx->cm_id->route.addr.dst_addr, resp.dst_size);\n	} else {\n		addr->sib_family = AF_IB;\n		addr->sib_pkey = (__force __be16) resp.pkey;\n		rdma_addr_get_dgid(&ctx->cm_id->route.addr.dev_addr,\n				   (union ib_gid *) &addr->sib_addr);\n		addr->sib_sid = rdma_get_service_id(ctx->cm_id, (struct sockaddr *)\n						    &ctx->cm_id->route.addr.dst_addr);\n	}\n\n	if (copy_to_user(response, &resp, sizeof(resp)))\n		ret = -EFAULT;\n\n	return ret;\n}\n\nstatic ssize_t query(struct file *file,\n			  const char __user *inbuf,\n			  int in_len, int out_len)\n{\n	struct rdma_ucm_query cmd;\n	struct context *ctx;\n	void __user *response;\n	int ret;\n\n	if (copy_from_user(&cmd, inbuf, sizeof(cmd)))\n		return -EFAULT;\n\n	response = (void __user *)(unsigned long) cmd.response;\n	ctx = get_ctx(file, cmd.id);\n	if (IS_ERR(ctx))\n		return PTR_ERR(ctx);\n\n	switch (cmd.option) {\n	case RDMA_USER_CM_QUERY_ADDR:\n		ret = query_addr(ctx, response, out_len);\n		break;\n	case RDMA_USER_CM_QUERY_PATH:\n		ret = query_path(ctx, response, out_len);\n		break;\n	case RDMA_USER_CM_QUERY_GID:\n		ret = query_gid(ctx, response, out_len);\n		break;\n	default:\n		ret = -ENOSYS;\n		break;\n	}\n\n	put_ctx(ctx);\n	return ret;\n}\n\nstatic void copy_conn_param(struct rdma_cm_id *id,\n				 struct rdma_conn_param *dst,\n				 struct rdma_ucm_conn_param *src)\n{\n	dst->private_data = src->private_data;\n	dst->private_data_len = src->private_data_len;\n	dst->responder_resources = src->responder_resources;\n	dst->initiator_depth = src->initiator_depth;\n	dst->flow_control = src->flow_control;\n	dst->retry_count = src->retry_count;\n	dst->rnr_retry_count = src->rnr_retry_count;\n	dst->srq = src->srq;\n	dst->qp_num = src->qp_num;\n	dst->qkey = (id->route.addr.src_addr.ss_family == AF_IB) ? src->qkey : 0;\n}\n\nstatic ssize_t connect(struct file *file, const char __user *inbuf,\n			    int in_len, int out_len)\n{\n	struct rdma_ucm_connect cmd;\n	struct rdma_conn_param conn_param;\n	struct context *ctx;\n	int ret;\n\n	if (copy_from_user(&cmd, inbuf, sizeof(cmd)))\n		return -EFAULT;\n\n	if (!cmd.conn_param.valid)\n		return -EINVAL;\n\n	ctx = get_ctx(file, cmd.id);\n	if (IS_ERR(ctx))\n		return PTR_ERR(ctx);\n\n	copy_conn_param(ctx->cm_id, &conn_param, &cmd.conn_param);\n	ret = rdma_connect(ctx->cm_id, &conn_param);\n	put_ctx(ctx);\n	return ret;\n}\n\nstatic ssize_t listen(struct file *file, const char __user *inbuf,\n			   int in_len, int out_len)\n{\n	struct rdma_ucm_listen cmd;\n	struct context *ctx;\n	int ret;\n\n	if (copy_from_user(&cmd, inbuf, sizeof(cmd)))\n		return -EFAULT;\n\n	ctx = get_ctx(file, cmd.id);\n	if (IS_ERR(ctx))\n		return PTR_ERR(ctx);\n\n	ctx->backlog = cmd.backlog > 0 && cmd.backlog < max_backlog ?\n		       cmd.backlog : max_backlog;\n	ret = rdma_listen(ctx->cm_id, ctx->backlog);\n	put_ctx(ctx);\n	return ret;\n}\n\nstatic ssize_t accept(struct file *file, const char __user *inbuf,\n			   int in_len, int out_len)\n{\n	struct rdma_ucm_accept cmd;\n	struct rdma_conn_param conn_param;\n	struct context *ctx;\n	int ret;\n\n	if (copy_from_user(&cmd, inbuf, sizeof(cmd)))\n		return -EFAULT;\n\n	ctx = get_ctx(file, cmd.id);\n	if (IS_ERR(ctx))\n		return PTR_ERR(ctx);\n\n	if (cmd.conn_param.valid) {\n		copy_conn_param(ctx->cm_id, &conn_param, &cmd.conn_param);\n		mutex_lock(&file->mut);\n		ret = rdma_accept(ctx->cm_id, &conn_param);\n		if (!ret)\n			ctx->uid = cmd.uid;\n		mutex_unlock(&file->mut);\n	} else\n		ret = rdma_accept(ctx->cm_id, NULL);\n\n	put_ctx(ctx);\n	return ret;\n}\n\nstatic ssize_t reject(struct file *file, const char __user *inbuf,\n			   int in_len, int out_len)\n{\n	struct rdma_ucm_reject cmd;\n	struct context *ctx;\n	int ret;\n\n	if (copy_from_user(&cmd, inbuf, sizeof(cmd)))\n		return -EFAULT;\n\n	ctx = get_ctx(file, cmd.id);\n	if (IS_ERR(ctx))\n		return PTR_ERR(ctx);\n\n	ret = rdma_reject(ctx->cm_id, cmd.private_data, cmd.private_data_len);\n	put_ctx(ctx);\n	return ret;\n}\n\nstatic ssize_t disconnect(struct file *file, const char __user *inbuf,\n			       int in_len, int out_len)\n{\n	struct rdma_ucm_disconnect cmd;\n	struct context *ctx;\n	int ret;\n\n	if (copy_from_user(&cmd, inbuf, sizeof(cmd)))\n		return -EFAULT;\n\n	ctx = get_ctx(file, cmd.id);\n	if (IS_ERR(ctx))\n		return PTR_ERR(ctx);\n\n	ret = rdma_disconnect(ctx->cm_id);\n	put_ctx(ctx);\n	return ret;\n}\n\nstatic ssize_t init_qp_attr(struct file *file,\n				 const char __user *inbuf,\n				 int in_len, int out_len)\n{\n	struct rdma_ucm_init_qp_attr cmd;\n	struct ib_uverbs_qp_attr resp;\n	struct context *ctx;\n	struct ib_qp_attr qp_attr;\n	int ret;\n\n	if (out_len < sizeof(resp))\n		return -ENOSPC;\n\n	if (copy_from_user(&cmd, inbuf, sizeof(cmd)))\n		return -EFAULT;\n\n	ctx = get_ctx(file, cmd.id);\n	if (IS_ERR(ctx))\n		return PTR_ERR(ctx);\n\n	resp.qp_attr_mask = 0;\n	memset(&qp_attr, 0, sizeof qp_attr);\n	qp_attr.qp_state = cmd.qp_state;\n	ret = rdma_init_qp_attr(ctx->cm_id, &qp_attr, &resp.qp_attr_mask);\n	if (ret)\n		goto out;\n\n	ib_copy_qp_attr_to_user(&resp, &qp_attr);\n	if (copy_to_user((void __user *)(unsigned long)cmd.response,\n			 &resp, sizeof(resp)))\n		ret = -EFAULT;\n\nout:\n	put_ctx(ctx);\n	return ret;\n}\n\nstatic int set_option_id(struct context *ctx, int optname,\n			      void *optval, size_t optlen)\n{\n	int ret = 0;\n\n	switch (optname) {\n	case RDMA_OPTION_ID_TOS:\n		if (optlen != sizeof(u8)) {\n			ret = -EINVAL;\n			break;\n		}\n		rdma_set_service_type(ctx->cm_id, *((u8 *) optval));\n		break;\n	case RDMA_OPTION_ID_REUSEADDR:\n		if (optlen != sizeof(int)) {\n			ret = -EINVAL;\n			break;\n		}\n		ret = rdma_set_reuseaddr(ctx->cm_id, *((int *) optval) ? 1 : 0);\n		break;\n	case RDMA_OPTION_ID_AFONLY:\n		if (optlen != sizeof(int)) {\n			ret = -EINVAL;\n			break;\n		}\n		ret = rdma_set_afonly(ctx->cm_id, *((int *) optval) ? 1 : 0);\n		break;\n	default:\n		ret = -ENOSYS;\n	}\n\n	return ret;\n}\n\nstatic int set_ib_path(struct context *ctx,\n			    struct ib_path_rec_data *path_data, size_t optlen)\n{\n	struct ib_sa_path_rec sa_path;\n	struct rdma_cm_event event;\n	int ret;\n\n	if (optlen % sizeof(*path_data))\n		return -EINVAL;\n\n	for (; optlen; optlen -= sizeof(*path_data), path_data++) {\n		if (path_data->flags == (IB_PATH_GMP | IB_PATH_PRIMARY |\n					 IB_PATH_BIDIRECTIONAL))\n			break;\n	}\n\n	if (!optlen)\n		return -EINVAL;\n\n	ib_sa_unpack_path(path_data->path_rec, &sa_path);\n	ret = rdma_set_ib_paths(ctx->cm_id, &sa_path, 1);\n	if (ret)\n		return ret;\n\n	memset(&event, 0, sizeof event);\n	event.event = RDMA_CM_EVENT_ROUTE_RESOLVED;\n	return event_handler(ctx->cm_id, &event);\n}\n\nstatic int set_option_ib(struct context *ctx, int optname,\n			      void *optval, size_t optlen)\n{\n	int ret;\n\n	switch (optname) {\n	case RDMA_OPTION_IB_PATH:\n		ret = set_ib_path(ctx, optval, optlen);\n		break;\n	default:\n		ret = -ENOSYS;\n	}\n\n	return ret;\n}\n\nstatic int set_option_level(struct context *ctx, int level,\n				 int optname, void *optval, size_t optlen)\n{\n	int ret;\n\n	switch (level) {\n	case RDMA_OPTION_ID:\n		ret = set_option_id(ctx, optname, optval, optlen);\n		break;\n	case RDMA_OPTION_IB:\n		ret = set_option_ib(ctx, optname, optval, optlen);\n		break;\n	default:\n		ret = -ENOSYS;\n	}\n\n	return ret;\n}\n\nstatic ssize_t set_option(struct file *file, const char __user *inbuf,\n			       int in_len, int out_len)\n{\n	struct rdma_ucm_set_option cmd;\n	struct context *ctx;\n	void *optval;\n	int ret;\n\n	if (copy_from_user(&cmd, inbuf, sizeof(cmd)))\n		return -EFAULT;\n\n	ctx = get_ctx(file, cmd.id);\n	if (IS_ERR(ctx))\n		return PTR_ERR(ctx);\n\n	optval = memdup_user((void __user *) (unsigned long) cmd.optval,\n			     cmd.optlen);\n	if (IS_ERR(optval)) {\n		ret = PTR_ERR(optval);\n		goto out;\n	}\n\n	ret = set_option_level(ctx, cmd.level, cmd.optname, optval,\n				    cmd.optlen);\n	kfree(optval);\n\nout:\n	put_ctx(ctx);\n	return ret;\n}\n\nstatic ssize_t notify(struct file *file, const char __user *inbuf,\n			   int in_len, int out_len)\n{\n	struct rdma_ucm_notify cmd;\n	struct context *ctx;\n	int ret;\n\n	if (copy_from_user(&cmd, inbuf, sizeof(cmd)))\n		return -EFAULT;\n\n	ctx = get_ctx(file, cmd.id);\n	if (IS_ERR(ctx))\n		return PTR_ERR(ctx);\n\n	ret = rdma_notify(ctx->cm_id, (enum ib_event_type) cmd.event);\n	put_ctx(ctx);\n	return ret;\n}\n\nstatic ssize_t process_join(struct file *file,\n				 struct rdma_ucm_join_mcast *cmd,  int out_len)\n{\n	struct rdma_ucm_create_id_resp resp;\n	struct context *ctx;\n	struct multicast *mc;\n	struct sockaddr *addr;\n	int ret;\n\n	if (out_len < sizeof(resp))\n		return -ENOSPC;\n\n	addr = (struct sockaddr *) &cmd->addr;\n	if (cmd->reserved || !cmd->addr_size || (cmd->addr_size != rdma_addr_size(addr)))\n		return -EINVAL;\n\n	ctx = get_ctx(file, cmd->id);\n	if (IS_ERR(ctx))\n		return PTR_ERR(ctx);\n\n	mutex_lock(&file->mut);\n	mc = alloc_multicast(ctx);\n	if (!mc) {\n		ret = -ENOMEM;\n		goto err1;\n	}\n\n	mc->uid = cmd->uid;\n	memcpy(&mc->addr, addr, cmd->addr_size);\n	ret = rdma_join_multicast(ctx->cm_id, (struct sockaddr *) &mc->addr, mc);\n	if (ret)\n		goto err2;\n\n	resp.id = mc->id;\n	if (copy_to_user((void __user *)(unsigned long) cmd->response,\n			 &resp, sizeof(resp))) {\n		ret = -EFAULT;\n		goto err3;\n	}\n\n	mutex_unlock(&file->mut);\n	put_ctx(ctx);\n	return 0;\n\nerr3:\n	rdma_leave_multicast(ctx->cm_id, (struct sockaddr *) &mc->addr);\n	cleanup_mc_events(mc);\nerr2:\n	mutex_lock(&mut);\n	idr_remove(&multicast_idr, mc->id);\n	mutex_unlock(&mut);\n	list_del(&mc->list);\n	kfree(mc);\nerr1:\n	mutex_unlock(&file->mut);\n	put_ctx(ctx);\n	return ret;\n}\n\nstatic ssize_t join_ip_multicast(struct file *file,\n				      const char __user *inbuf,\n				      int in_len, int out_len)\n{\n	struct rdma_ucm_join_ip_mcast cmd;\n	struct rdma_ucm_join_mcast join_cmd;\n\n	if (copy_from_user(&cmd, inbuf, sizeof(cmd)))\n		return -EFAULT;\n\n	join_cmd.response = cmd.response;\n	join_cmd.uid = cmd.uid;\n	join_cmd.id = cmd.id;\n	join_cmd.addr_size = rdma_addr_size((struct sockaddr *) &cmd.addr);\n	join_cmd.reserved = 0;\n	memcpy(&join_cmd.addr, &cmd.addr, join_cmd.addr_size);\n\n	return process_join(file, &join_cmd, out_len);\n}\n\nstatic ssize_t join_multicast(struct file *file,\n				   const char __user *inbuf,\n				   int in_len, int out_len)\n{\n	struct rdma_ucm_join_mcast cmd;\n\n	if (copy_from_user(&cmd, inbuf, sizeof(cmd)))\n		return -EFAULT;\n\n	return process_join(file, &cmd, out_len);\n}\n\nstatic ssize_t leave_multicast(struct file *file,\n				    const char __user *inbuf,\n				    int in_len, int out_len)\n{\n	struct rdma_ucm_destroy_id cmd;\n	struct rdma_ucm_destroy_id_resp resp;\n	struct multicast *mc;\n	int ret = 0;\n\n	if (out_len < sizeof(resp))\n		return -ENOSPC;\n\n	if (copy_from_user(&cmd, inbuf, sizeof(cmd)))\n		return -EFAULT;\n\n	mutex_lock(&mut);\n	mc = idr_find(&multicast_idr, cmd.id);\n	if (!mc)\n		mc = ERR_PTR(-ENOENT);\n	else if (mc->ctx->file != file)\n		mc = ERR_PTR(-EINVAL);\n	else {\n		idr_remove(&multicast_idr, mc->id);\n		atomic_inc(&mc->ctx->ref);\n	}\n	mutex_unlock(&mut);\n\n	if (IS_ERR(mc)) {\n		ret = PTR_ERR(mc);\n		goto out;\n	}\n\n	rdma_leave_multicast(mc->ctx->cm_id, (struct sockaddr *) &mc->addr);\n	mutex_lock(&mc->ctx->file->mut);\n	cleanup_mc_events(mc);\n	list_del(&mc->list);\n	mutex_unlock(&mc->ctx->file->mut);\n\n	put_ctx(mc->ctx);\n	resp.events_reported = mc->events_reported;\n	kfree(mc);\n\n	if (copy_to_user((void __user *)(unsigned long)cmd.response,\n			 &resp, sizeof(resp)))\n		ret = -EFAULT;\nout:\n	return ret;\n}\n\nstatic void lock_files(struct file *file1, struct file *file2)\n{\n	/* Acquire mutex\'s based on pointer comparison to prevent deadlock. */\n	if (file1 < file2) {\n		mutex_lock(&file1->mut);\n		mutex_lock(&file2->mut);\n	} else {\n		mutex_lock(&file2->mut);\n		mutex_lock(&file1->mut);\n	}\n}\n\nstatic void unlock_files(struct file *file1, struct file *file2)\n{\n	if (file1 < file2) {\n		mutex_unlock(&file2->mut);\n		mutex_unlock(&file1->mut);\n	} else {\n		mutex_unlock(&file1->mut);\n		mutex_unlock(&file2->mut);\n	}\n}\n\nstatic void move_events(struct context *ctx, struct file *file)\n{\n	struct event *uevent, *tmp;\n\n	list_for_each_entry_safe(uevent, tmp, &ctx->file->event_list, list)\n		if (uevent->ctx == ctx)\n			list_move_tail(&uevent->list, &file->event_list);\n}\n\nstatic ssize_t migrate_id(struct file *new_file,\n			       const char __user *inbuf,\n			       int in_len, int out_len)\n{\n	struct rdma_ucm_migrate_id cmd;\n	struct rdma_ucm_migrate_resp resp;\n	struct context *ctx;\n	struct fd f;\n	struct file *cur_file;\n	int ret = 0;\n\n	if (copy_from_user(&cmd, inbuf, sizeof(cmd)))\n		return -EFAULT;\n\n	/* Get current fd to protect against it being closed */\n	f = fdget(cmd.fd);\n	if (!f.file)\n		return -ENOENT;\n\n	/* Validate current fd and prevent destruction of id. */\n	ctx = get_ctx(f.file->private_data, cmd.id);\n	if (IS_ERR(ctx)) {\n		ret = PTR_ERR(ctx);\n		goto file_put;\n	}\n\n	cur_file = ctx->file;\n	if (cur_file == new_file) {\n		resp.events_reported = ctx->events_reported;\n		goto response;\n	}\n\n	/*\n	 * Migrate events between fd\'s, maintaining order, and avoiding new\n	 * events being added before existing events.\n	 */\n	lock_files(cur_file, new_file);\n	mutex_lock(&mut);\n\n	list_move_tail(&ctx->list, &new_file->ctx_list);\n	move_events(ctx, new_file);\n	ctx->file = new_file;\n	resp.events_reported = ctx->events_reported;\n\n	mutex_unlock(&mut);\n	unlock_files(cur_file, new_file);\n\nresponse:\n	if (copy_to_user((void __user *)(unsigned long)cmd.response,\n			 &resp, sizeof(resp)))\n		ret = -EFAULT;\n\n	put_ctx(ctx);\nfile_put:\n	fdput(f);\n	return ret;\n}\n\n\n\n';
var sandboxText;

function initSandbox() {
	sandboxText = escapedSource;
}

function randomInt(min, max) {
		min = (min === undefined) ? 0 : min;
		max = (max === undefined) ? 255 : max;
		return Math.floor(Math.random()*(max - min)) + min;
}

function repeatString(pattern, count) {
    if (count < 1) return '';
    var result = '';
    while (count > 1) {
        if (count & 1) result += pattern;
        count >>= 1, pattern += pattern;
    }
    return result + pattern;
}

function hexDigit() {
	var digits = '0123456789abcdef';
	return digits.charAt( Math.floor(Math.random()*(digits.length-1)) );
}

function AsmGenerator() {

	this.registers = {
		'64' : ['rax', 'rbx', 'rcx', 'rdx'],
		'32' : ['eax', 'eax', 'ecx', 'edx'],
		'16' : ['ax', 'bx', 'cx', 'dx'],
		'8'  : ['ah', 'al', 'bh', 'bl', 'ch', 'cl', 'dh', 'dl'],
		'wp' : ['rdi', 'rsi', 'rbp', 'rsp', 'edi', 'esi', 'ebp', 'esp'],
		'rp' : ['rip', 'eip']
	};
	
	// %ar (add,adc,sub,and,or,xor)
	// %reg, %wrg, %mem, %lit, %lt8, %lab
	this.operations = {
		'move' : [
			['mov',  '%wrg', '%reg'],
			['mov',  '%wrg', '%mem'],
			['mov',  '%mem', '%reg'],
			['mov',  '%wrg', '%lit'],
			['mov',  '%mem', '%lit']
		],
		'stack' : [
			['push', '%wrg'],
			['push', '%mem'],
			['push', '%lit'],
			['pop',  '%wrg'],
			['pop',  '%mem']
		],
		'jump' : [
			['je',   '%lab'],
			['jne',  '%lab'],
			['call', '%lab']
		],
		'calc' : [
			['lea',  '%wrg', '%mem'],
			['test', '%reg', '%reg'],
			['test', '%reg', '%mem'],
			['test', '%reg', '%lit'],
			['cmp', '%reg', '%reg'],
			['cmp', '%reg', '%mem'],
			['cmp', '%mem', '%reg'],
			['cmp', '%reg', '%lit']
		],
		'arithmetic' : [
			['%ar',  '%wrg', '%reg'],
			['%ar',  '%wrg', '%mem'],
			['%ar',  '%mem', '%reg'],
			['%ar',  '%wrg', '%lit'],
			['%ar',  '%mem', '%lit']
		],
		'arithmetic2' : [
			['inc',  '%wrg'],
			['inc',  '%mem'],
			['dec',  '%wrg'],
			['dec',  '%mem'],
			['shl',  '%wrg', '%lt8'],
			['shr',  '%mem', '%lt8'],
			['not',  '%wrg'],
			['not',  '%mem'],
			['neg',  '%wrg'],
			['neg',  '%mem']
		],
		'other' : [
			['imul', '%wrg', '%reg'],
			['imul', '%wrg', '%mem'],
			['imul', '%wrg', '%reg', '%lit'],
			['imul', '%wrg', '%mem', '%lit'],
			['idiv', '%wrg'],
			['idiv', '%mem'],
			['int',  '%lt8']
		]
	};
	
	this.assembleOperation = function(opArray) {
		var html = '&nbsp;&nbsp;';
		var separator = ', ';
		for (var i=0; i<opArray.length; i++) {
			if (opArray[i].charAt(0) != '%') {
				// plaintext
				html += '<span>' + opArray[i] + '</span>' + ' ';
			} else {
				// wildcard
				html += 
					'<span class="' + opArray[i].slice(1) + '">' +
					this.resolveWildcard(opArray[i].slice(1)) +
					'</span>' +
					((i == 0) ? ' ' : separator)
				;
			}
		}
		html = html.slice(0, -separator.length);
		return html;
	};
	
	this.randomOpArray = function(category) {
		return this.operations[category][this.randomInt(0, this.operations[category].length-1)];
	};
	
	this.generateOperation = function() {
		var dice = this.randomInt(0, 100);
		if (dice > 65) return this.assembleOperation(this.randomOpArray('move'));
		if (dice > 50) return this.assembleOperation(this.randomOpArray('stack'));
		if (dice > 40) return this.assembleOperation(this.randomOpArray('jump'));
		if (dice > 30) return this.assembleOperation(this.randomOpArray('calc'));
		if (dice > 20) return this.assembleOperation(this.randomOpArray('arithmetic'));
		if (dice > 15) return this.assembleOperation(this.randomOpArray('arithmetic2'));
		if (dice > 10) return this.assembleOperation(this.randomOpArray('other'));
		return '.<span class="lab">' + this.generateLabel() + '</span>:';
	};
	
	this.resolveWildcard = function(wildcard) {
		switch (wildcard) {
			case 'reg': return this.generateRegister(false);
			case 'wrg': return this.generateRegister(true);
			case 'lab':	return this.generateLabel();
			case 'lt8':	return this.generateByte();
			case 'lit':	return this.generateHexLiteral(this.randomInt(2,5));
			case 'ar' : return this.randomArithmetic();
			case 'mem':	return this.generateAddress();
			default   : return 'undefined_wildcard';
		}
	};
	
	this.generateAddress = function() {
		var ops = '+*';
		var address = '';
		if (Math.random() > 0.7) {
			address += this.generateWidth() + ' ';
		}
		address += '[';
		address += this.generateRegister(false);
		if (Math.random() > 0.8) {
			address += ops.charAt(this.randomInt(0, ops.lenght-1));
			address += this.generateRegister();
		}
		if (Math.random() > 0.4) {
			address += ops.charAt(this.randomInt(0, ops.lenght-1));
			address += this.randomInt(0,31);
		}
		address += ']';
		return address;
	};
	
	this.randomArithmetic = function() {
		var ops = ['add','adc','sub','and','or','xor'];
		return ops[Math.floor(Math.random()*(ops.length-1))];
	};
	
	this.generateByte = function() {
		// random hex or dec
		if (Math.random() > 0.5) {
			return this.generateHexLiteral(2, Math.random() > 0.5);
		} else {
			return this.randomInt(0, 255);
		}
	};
	
	this.generateLabel = function() {
		var words = ['init', 'test', 'access', 'turn', 'prc', 'mod', 'load'];
		var letters = 'befhklpqrstwxyz';
		var limit = 512;
		return  words[this.randomInt(0, words.length-1)] +
				this.randomInt(0, limit) +
				letters.charAt(this.randomInt(0, letters.length-1))
		;
	};
	
	this.generateWidth = function() {
		var widths = ['byte', 'word', 'dword', 'qword'];
		return widths[Math.floor(Math.random()*(widths.length-1))];
	};

	this.generateHexDigit = function(uppercase) {
		uppercase = (uppercase === undefined) ? false : true;
		var digits = '0123456789abcdef';
		if (uppercase) {
			digits = digits.toUpperCase();
		}
		return digits.charAt( Math.floor(Math.random()*(digits.length-1)) );
	};
	
	this.randomInt = function(min, max) {
		min = (min === undefined) ? 0 : min;
		max = (max === undefined) ? 255 : max;
		return Math.floor(Math.random()*(max - min)) + min;
	};
	
	this.generateHexLiteral = function(count, uppercase) {
		count = (count === undefined) ? 1 : count;
		uppercase = (uppercase === undefined) ? false : true;
		var literal = '0';
		for (var i=0; i<count; i++) {
			literal += this.generateHexDigit(uppercase);
		}
		literal += uppercase ? 'H' : 'h';
		return literal;
	};
	
	this.getRegister = function(key) {
		return this.registers[key][this.randomInt(0, this.registers[key].length-1)]
	};
	
	this.generateRegister = function(writable) {
		writable = (writable === undefined) ? true : false;
		var dice = this.randomInt(0, 100);
		if (dice > 80) return this.getRegister('64');
		if (dice > 30) return this.getRegister('32');
		if (dice > 20) return this.getRegister('16');
		if (dice > 10) return this.getRegister('wp');
		if (!writable || dice > 5) return this.getRegister('8');
		return this.getRegister('rp');
	};
}

function HexDumpGenerator() {
	
	this.generateDigit = function() {
		var digits = '0123456789abcdef';
		return digits.charAt( Math.floor(Math.random()*(digits.length-1)) );
	};
	
	this.generateLiteral = function(count) {
		var literal = '';
		for(var i=0; i<count; i++) {
			literal += this.generateDigit();
		}
		return literal;
	};
	
	this.generateLabel = function(count) {
		return '<span class="hexlabel">0x' + this.generateLiteral(count) + ':</span>';
	};
	
	this.generateLine = function(count) {
		var line = this.generateLabel + '&nbsp;';
		for(var i=0; i<count; i++) {
			line += '&nbsp;' + this.generateLiteral(4);
		}
		line += '<br>';
		return line;
	};
	
}

function IpTraffic() {
	
	this.protocols = ['IP', 'TCP', 'UDP', 'ICMP', 'ARP', 'HTTP'];
	
	this.generateByte = function() {
		return randomInt(1, 255);
	};
	
	this.generateIPv4Address = function() {
		return (
			this.generateByte() + '.' +
			this.generateByte() + '.' +
			this.generateByte() + '.' +
			this.generateByte()
		);
	};
	
	this.generateProtocol = function() {
		return this.protocols[randomInt(0, this.protocols.length)];
	};
	
	this.generatePort = function() {
		return randomInt(0, 65535);
	};
	
	this.generateRequest = function() {
		return (
			'<tr>' +
			'<td style="width:12%;padding-left:2%;"><span class="protocol">' +
				this.generateProtocol() +
			'</span></td>' +
			'<td style="width:10%;text-align:center;"><span class="request_separator">' +
				'&gt;' +
			'</span></td>' +
			'<td style="width:50%;"><span class="ipv4">' +
				this.generateIPv4Address() +
			'</span></td>' +
			'<td style="text-align:left;"><span class="progressbar">' +
				repeatString('&#9646;', randomInt(1,10)) +
			'</span></td>' +
			'</tr>'
			// &#9646;
		);
	};
	
}

$(function() {
	
	var sandbox = $("#sandbox");
	var code = $("#sandbox #code");
	var cursor = $("#sandbox .block_cursor");
	var asm = $("#assembly");
	var top = $("#top_panel");
	var left = $("#left_column");
	var iptraf = $("#iptraf");
	var gen = new AsmGenerator();
	var dumpgen = new HexDumpGenerator();
	var trafgen = new IpTraffic();
	initSandbox();
	
	$("*").css("font-size", window.innerWidth/85+"px");
	$(".block_cursor").css("font-size", window.innerWidth/65+"px");
	
	var greens = '89abcd';
	$("body").keydown(function(e) {
		var chunk = sandboxText.slice(0,3);
		chunk = chunk.replace(/\n/g, '<br>');
		chunk = chunk.replace(/\t/g, '&nbsp;&nbsp;&nbsp;&nbsp;');
		chunk = chunk.replace(/ /g, '&nbsp;');
		chunk = '<span style="color:#0'+greens.charAt(randomInt(0, greens.length))+'2;">' + chunk + '</span>';
		code.append(chunk);
		sandboxText = sandboxText.slice(3,-1);
		sandboxText.length || initSandbox();
		sandbox[0].scrollTop = sandbox[0].scrollHeight;
	});
	
	var bar_rows = 5;
	var bar_cols = 28;
	for(var i=0; i<bar_rows; i++) {
		var row = '<tr>';
		for(var j=0; j<bar_cols; j++) {
			row += '<td></td>';
		}
		row += '</tr>';
		$("#bars").append(row);
	}
	$("#bars td")
		.css("width", 100/bar_cols+"%")
		.css("height", 100/bar_rows+"%")
	;
	
	var row_count = 6;
	var col_count = 16;
	for(var i=0; i<row_count; i++) {
		$("#bottom_panel").append('<div id="bottom_row'+i+'"></div>');
		$("#bottom_row"+i)
			.css("position", "absolute")
			.css("left", "0")
			.css("right", "0")
			.css("top", i*100/row_count+"%")
			.css("bottom", 100-(i+1)*100/row_count+"%")
		;
		for(var j=0; j<col_count; j++) {
			$("#bottom_row"+i).append('<div class="bottom_col'+j+'" style="position:absolute;"></div>');
		}
	}
	
	for(var j=0; j<col_count; j++) {
		$(".bottom_col"+j)
			.css("left",j*100/col_count+"%")
			.css("right",100-(j+1)*100/col_count+"%")
			.css("top", "0")
			.css("bottom", "0")
		;
	}
	
	$("#bottom_panel > div > div").each(function() {
		$(this).css("text-align", "center");
		$(this).css("line-height", $(this).css("height"));
		$(this).css("color", "#5bb");
		$(this).html(dumpgen.generateLiteral(4));
	});
	
	setInterval(function() {
		if (cursor.css('display') == 'none') {
			cursor.css('display', 'inline');
		} else {
			cursor.css('display', 'none');
		}
	}, 400);
		
	setInterval(function() {
		asm.append(gen.generateOperation());
		asm.append('<br/>');
		asm[0].scrollTop = asm[0].scrollHeight;
	}, 150);

	var bottom_matrix = $("#bottom_panel > div > div");
	var bottom_idx = 0;
	setInterval(function() {
		bottom_matrix
			.eq(bottom_idx++)
			.html(randomInt(0,10)<9 ? dumpgen.generateLiteral(4) : randomInt(0,2) ? 'XXXX' : '----')
		;
		bottom_idx = (bottom_idx == row_count*col_count)? 0 : bottom_idx;
	}, 30);
	
	var bar_row = $("#bars tr");
	setInterval(function() {
		bar_row
			.eq(randomInt(0,bar_cols))
			.css("background-color", randomInt(0,2)?"rgba(160,250,160,0.35)":"rgba(50,70,50,0.35)")
		;
	}, 500);
	
	var bar_matrix = $("#bars td");
	var matrix_values = ['0', '1', '-', ''];
	setInterval(function() {
		bar_matrix
			.eq(randomInt(0,bar_cols*bar_rows))
			.html(matrix_values[randomInt(0,matrix_values.length)]);
		;
	}, 100);
	
	setInterval(function() {
		iptraf.append(trafgen.generateRequest());
		//left[0].scrollTop = left[0].scrollHeight;
	}, 800);
	
});