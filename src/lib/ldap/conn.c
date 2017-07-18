

/** Close and delete a connection
 *
 * Unbinds the LDAP connection, informing the server and freeing any memory, then releases the memory used by the
 * connection handle.
 *
 * @param conn to destroy.
 * @return always indicates success.
 */
static int _mod_conn_free_async(fr_ldap_conn_t *conn)
{
	fr_ldap_handle_config_t const	*handle_config = conn->config;

	rad_assert(conn->handle);

	talloc_free_children(conn);	/* Force inverted free order */

	fr_ldap_control_clear(conn);

#ifdef HAVE_LDAP_UNBIND_EXT_S
	LDAPControl	*our_serverctrls[LDAP_MAX_CONTROLS];
	LDAPControl	*our_clientctrls[LDAP_MAX_CONTROLS];

	fr_ldap_control_merge(our_serverctrls, our_clientctrls,
			      sizeof(our_serverctrls) / sizeof(*our_serverctrls),
			      sizeof(our_clientctrls) / sizeof(*our_clientctrls),
			      conn, NULL, NULL);

	DEBUG3("Closing libldap handle %p", conn->handle);
	ldap_unbind_ext(conn->handle, our_serverctrls, our_clientctrls);	/* Same code as ldap_unbind_ext_s */
#else
	DEBUG3("Closing libldap handle %p", conn->handle);
	ldap_unbind(conn->handle);						/* Same code as ldap_unbind_s */
#endif
	conn->handle = NULL;

	return 0;
}

/** Allocate and configure a new connection
 *
 * Allocates and configures both our ldap handle, and libldap's handle.
 *
 * This can be used by async code and async code as no attempt is made to connect
 * to the LDAP server.  An attempt will only be made if ldap_start_tls* or ldap_bind*
 * functions are called.
 *
 * @param[in] ctx		to allocate handle in.
 * @param[in] handle_config	Connection configuration.
 * @return
 *	- A new handle on success.
 *	- NULL on error.
 */
fr_ldap_conn_t *fr_ldap_conn_configure(TALLOC_CTX *ctx, fr_ldap_handle_config_t const *handle_config)
{
	fr_ldap_conn_t			*conn;
	LDAP				*handle = NULL;

	int				ldap_errno, ldap_version;

	rad_assert(handle_config->server);

#ifdef HAVE_LDAP_INITIALIZE
	ldap_errno = ldap_initialize(&handle, handle_config->server);
	if (ldap_errno != LDAP_SUCCESS) {
		ERROR("ldap_initialize failed: %s", ldap_err2string(ldap_errno));
		return NULL;
	}
#else
	handle = ldap_init(handle_config->server, handle_config->port);
	if (!handle) {
		ERROR("ldap_init failed");
		return NULL;
	}
#endif

	DEBUG3("New libldap handle %p", handle);

	/*
	 *	Allocate memory for the handle.
	 */
	conn = talloc_zero(ctx, fr_ldap_conn_t);
	if (!conn) return NULL;

	conn->config = handle_config;
	conn->handle = handle;
	conn->rebound = false;
	conn->referred = false;

	talloc_set_destructor(conn, _mod_conn_free_async);

	/*
	 *	We now have a connection structure, but no actual connection.
	 *
	 *	Set a bunch of LDAP options, using common code.
	 */
#define do_ldap_option(_option, _name, _value) \
	if (ldap_set_option(conn->handle, _option, _value) != LDAP_OPT_SUCCESS) { \
		ldap_get_option(conn->handle, LDAP_OPT_ERROR_NUMBER, &ldap_errno); \
		ERROR("Failed setting connection option %s: %s", _name, \
		      (ldap_errno != LDAP_SUCCESS) ? ldap_err2string(ldap_errno) : "Unknown error"); \
		goto error;\
	}

#define maybe_ldap_option(_option, _name, _value) \
	if (_value) do_ldap_option(_option, _name, _value)

	/*
	 *	Leave "dereference" unset to use the OpenLDAP default.
	 */
	if (handle_config->dereference_str) {
		do_ldap_option(LDAP_OPT_DEREF, "dereference", &(handle_config->dereference));
	}

	/*
	 *	Leave "chase_referrals" unset to use the OpenLDAP default.
	 */
	if (!handle_config->chase_referrals_unset) {
		if (handle_config->chase_referrals) {
			do_ldap_option(LDAP_OPT_REFERRALS, "chase_referrals", LDAP_OPT_ON);

			if (handle_config->rebind == true) {
#if LDAP_SET_REBIND_PROC_ARGS == 3
				ldap_set_rebind_proc(conn->handle, fr_ldap_rebind, conn);
#endif
			}
		} else {
			do_ldap_option(LDAP_OPT_REFERRALS, "chase_referrals", LDAP_OPT_OFF);
		}
	}

#ifdef LDAP_OPT_NETWORK_TIMEOUT
	/*
	 *	A value of zero results in an handle configuration failure.
	 *
	 *	When most people specify zero they mean infinite.
	 *
	 *	libldap requires tv_sec to be -1 to mean that.
	 */
	{
		struct timeval ldap_timeout = handle_config->net_timeout;

		if ((ldap_timeout.tv_usec == 0) && (ldap_timeout.tv_sec == 0)) ldap_timeout.tv_sec = -1;

		do_ldap_option(LDAP_OPT_NETWORK_TIMEOUT, "net_timeout", &ldap_timeout);
	}
#endif

	do_ldap_option(LDAP_OPT_TIMELIMIT, "srv_timelimit", &(handle_config->srv_timelimit));

	ldap_version = LDAP_VERSION3;
	do_ldap_option(LDAP_OPT_PROTOCOL_VERSION, "ldap_version", &ldap_version);

#ifdef LDAP_OPT_X_KEEPALIVE_IDLE
	do_ldap_option(LDAP_OPT_X_KEEPALIVE_IDLE, "keepalive_idle", &(handle_config->keepalive_idle));
#endif

#ifdef LDAP_OPT_X_KEEPALIVE_PROBES
	do_ldap_option(LDAP_OPT_X_KEEPALIVE_PROBES, "keepalive_probes", &(handle_config->keepalive_probes));
#endif

#ifdef LDAP_OPT_X_KEEPALIVE_INTERVAL
	do_ldap_option(LDAP_OPT_X_KEEPALIVE_INTERVAL, "keepalive_interval", &(handle_config->keepalive_interval));
#endif

#ifdef HAVE_LDAP_START_TLS_S
	/*
	 *	Set all of the TLS options
	 */
	if (handle_config->tls_mode) do_ldap_option(LDAP_OPT_X_TLS, "tls_mode", &(handle_config->tls_mode));

	maybe_ldap_option(LDAP_OPT_X_TLS_CACERTFILE, "ca_file", handle_config->tls_ca_file);
	maybe_ldap_option(LDAP_OPT_X_TLS_CACERTDIR, "ca_path", handle_config->tls_ca_path);

	/*
	 *	Set certificate options
	 */
	maybe_ldap_option(LDAP_OPT_X_TLS_CERTFILE, "certificate_file", handle_config->tls_certificate_file);
	maybe_ldap_option(LDAP_OPT_X_TLS_KEYFILE, "private_key_file", handle_config->tls_private_key_file);

#  ifdef LDAP_OPT_X_TLS_NEVER
	if (handle_config->tls_require_cert_str) {
		do_ldap_option(LDAP_OPT_X_TLS_REQUIRE_CERT, "require_cert", &handle_config->tls_require_cert);
	}
#  endif

	/*
	 *	Counter intuitively the TLS context appears to need to be initialised
	 *	after all the TLS options are set on the handle.
	 */
#  ifdef LDAP_OPT_X_TLS_NEWCTX
	{
		/* Always use the new TLS configuration context */
		int is_server = 0;
		do_ldap_option(LDAP_OPT_X_TLS_NEWCTX, "new TLS context", &is_server);
	}
#  endif

	if (handle_config->start_tls) {
		if (handle_config->port == 636) {
			WARN("Told to Start TLS on LDAPS port this will probably fail, please correct the "
			     "configuration");
		}
	}
#endif /* HAVE_LDAP_START_TLS_S */

	conn->config = handle_config;

	return conn;

error:
	talloc_free(conn);

	return NULL;
}

/** Send an extended operation to the LDAP server, requesting a transition to TLS
 *
 * Behind the scenes ldap_start_tls calls:
 *
 *	ldap_extended_operation(ld, LDAP_EXOP_START_TLS, NULL, serverctrls, clientctrls, msgidp);
 *
 * After getting a response (connection becomes writable), we call ldap_install_tls.  This funcion
 * attempts to retrieve any outstanding responses, and then installs TLS handlers.
 *
 */
static int fr_ldap_conn_start_tls_async(fr_ldap_conn_t *conn)
{
	int		msgid = 0;
	int		ret;

	LDAPControl	*our_serverctrls[LDAP_MAX_CONTROLS];
	LDAPControl	*our_clientctrls[LDAP_MAX_CONTROLS];

	fr_ldap_control_merge(our_serverctrls, our_clientctrls,
			      sizeof(our_serverctrls) / sizeof(*our_serverctrls),
			      sizeof(our_clientctrls) / sizeof(*our_clientctrls),
			      conn, NULL, NULL);

	ret = ldap_start_tls(conn->handle, our_serverctrls, our_clientctrls, &msgid);
	if (ret < 0) {
		ERROR("ldap_start_tls failed: %s",  ldap_err2string(ldap_errno));
		return -1;
	}
}

static fr_connection_state_t _ldap_conn_init(int *fd_out, void *uctx)
{

}

static fr_connection_state_t _ldap_conn_open(int fd, fr_event_list_t *el, void *uctx)
{

}

static  fr_connection_state_t _ldap_conn_failed(int fd, fr_connection_state_t state, void *uctx)
{

}

static void _ldap_conn_close(int fd, void *uctx)
{

}

fr_connection_t *fr_ldap_conn_alloc(TALLOC_CTX *ctx, fr_event_list_t *el,
				    fr_ldap_handle_config_t const *handle_config, char *log_prefix)
{
	fr_connection_t *conn;

	conn = fr_connection_alloc(ctx, el, handle_config->net_timeout, handle_config->reconnect_delay,
				   _ldap_conn_init, _ldap_conn_open, _ldap_conn_fail, log_prefix, handle_config);
	if (!conn) return NULL;

	fr_connection_failed_func(conn, _ldap_conn_failed);

	return conn;
}

int fr_ldap_conn_timeout_set(fr_ldap_conn_t const *conn, struct timeval const *timeout)
{
	int				ldap_errno;
	fr_ldap_handle_config_t const	*handle_config = conn->config;

#ifdef LDAP_OPT_NETWORK_TIMEOUT
	/*
	 *	A value of zero results in an handle configuration failure.
	 *
	 *	When most people specify zero they mean infinite.
	 *
	 *	libldap requires tv_sec to be -1 to mean that.
	 */
	{
		struct timeval ldap_timeout = *timeout;

		if ((ldap_timeout.tv_usec == 0) && (ldap_timeout.tv_sec == 0)) ldap_timeout.tv_sec = -1;

		do_ldap_option(LDAP_OPT_NETWORK_TIMEOUT, "net_timeout", &ldap_timeout);
	}
#endif

	return 0;

error:
	return -1;
}

int fr_ldap_conn_timeout_reset(fr_ldap_conn_t const *conn)
{
	int				ldap_errno;
	fr_ldap_handle_config_t const	*handle_config = conn->config;

#ifdef LDAP_OPT_NETWORK_TIMEOUT
	/*
	 *	A value of zero results in an handle configuration failure.
	 *
	 *	When most people specify zero they mean infinite.
	 *
	 *	libldap requires tv_sec to be -1 to mean that.
	 */
	{
		struct timeval ldap_timeout = handle_config->net_timeout;

		if ((ldap_timeout.tv_usec == 0) && (ldap_timeout.tv_sec == 0)) ldap_timeout.tv_sec = -1;

		do_ldap_option(LDAP_OPT_NETWORK_TIMEOUT, "net_timeout", &ldap_timeout);
	}
#endif

	return 0;

error:
	return -1;
}
