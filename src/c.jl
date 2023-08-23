const aws_allocator = Cvoid

function aws_default_allocator()
    ccall((:aws_default_allocator, libawscrt), Ptr{aws_allocator}, ())
end

function aws_mem_calloc(allocator, num, size)
    ccall((:aws_mem_calloc, libawscrt), Ptr{Cvoid}, (Ptr{aws_allocator}, Csize_t, Csize_t), allocator, num, size)
end

function aws_mem_acquire(allocator, size)
    ccall((:aws_mem_acquire, libawscrt), Ptr{Cvoid}, (Ptr{aws_allocator}, Csize_t), allocator, size)
end

function aws_mem_release(allocator, ptr)
    ccall((:aws_mem_release, libawscrt), Cvoid, (Ptr{Cvoid}, Ptr{Cvoid}), allocator, ptr)
end

function aws_last_error()
    ccall((:aws_last_error, libawscrt), Cint, ())
end

function aws_error_debug_str(err)
    ccall((:aws_error_debug_str, libawscrt), Ptr{Cchar}, (Cint,), err)
end

struct AWSError <: Exception
    msg::String
end

aws_error() = AWSError(unsafe_string(aws_error_debug_str(aws_last_error())))
aws_throw_error() = throw(aws_error())

@enum aws_log_level::UInt32 begin
    AWS_LL_NONE = 0
    AWS_LL_FATAL = 1
    AWS_LL_ERROR = 2
    AWS_LL_WARN = 3
    AWS_LL_INFO = 4
    AWS_LL_DEBUG = 5
    AWS_LL_TRACE = 6
    AWS_LL_COUNT = 7
end

const aws_logger = Cvoid

mutable struct aws_logger_standard_options
    level::aws_log_level
    filename::Ptr{Cchar}
    file::Libc.FILE
end

aws_logger_standard_options(level, file) = aws_logger_standard_options(aws_log_level(level), C_NULL, file)

function aws_logger_set_log_level(logger, level)
    ccall((:aws_logger_set_log_level, libawscrt), Cint, (Ptr{aws_logger}, aws_log_level), logger, level)
end

function aws_logger_init_standard(logger, allocator, options)
    ccall((:aws_logger_init_standard, libawscrt), Cint, (Ptr{aws_logger}, Ptr{aws_allocator}, Ref{aws_logger_standard_options}), logger, allocator, options)
end

function aws_logger_set(logger)
    ccall((:aws_logger_set, libawscrt), Cvoid, (Ptr{aws_logger},), logger)
end

function aws_http_library_init(alloc)
    ccall((:aws_http_library_init, libawscrt), Cvoid, (Ptr{aws_allocator},), alloc)
end

struct aws_byte_cursor
    len::Csize_t
    ptr::Ptr{UInt8}
end

aws_byte_cursor() = aws_byte_cursor(0, C_NULL)

function aws_byte_cursor_from_c_str(c_str)
    ccall((:aws_byte_cursor_from_c_str, libawscrt), aws_byte_cursor, (Ptr{Cchar},), c_str)
end

function aws_byte_cursor_eq_c_str_ignore_case(cursor, c_str)
    ccall((:aws_byte_cursor_eq_c_str_ignore_case, libawscrt), Bool, (Ref{aws_byte_cursor}, Ptr{Cchar}), cursor, c_str)
end

const aws_input_stream = Cvoid

function aws_input_stream_new_from_cursor(allocator, cursor)
    ccall((:aws_input_stream_new_from_cursor, libawscrt), Ptr{aws_input_stream}, (Ptr{aws_allocator}, Ref{aws_byte_cursor}), allocator, cursor)
end

function aws_input_stream_new_from_open_file(allocator, file)
    ccall((:aws_input_stream_new_from_open_file, libawscrt), Ptr{aws_input_stream}, (Ptr{aws_allocator}, Ptr{Libc.FILE}), allocator, file)
end

function aws_input_stream_get_length(stream, out_length)
    ccall((:aws_input_stream_get_length, libawscrt), Cint, (Ptr{aws_input_stream}, Ptr{Int64}), stream, out_length)
end

function aws_input_stream_destroy(stream)
    ccall((:aws_input_stream_destroy, libawscrt), Cvoid, (Ptr{aws_input_stream},), stream)
end

struct aws_byte_buf
    len::Csize_t
    buffer::Ptr{UInt8}
    capacity::Csize_t
    allocator::Ptr{aws_allocator}
end

aws_byte_buf() = aws_byte_buf(0, C_NULL, 0, C_NULL)

mutable struct aws_uri
    self_size::Csize_t
    allocator::Ptr{aws_allocator}
    uri_str::aws_byte_buf
    scheme::aws_byte_cursor
    authority::aws_byte_cursor
    userinfo::aws_byte_cursor
    user::aws_byte_cursor
    password::aws_byte_cursor
    host_name::aws_byte_cursor
    port::UInt16
    path::aws_byte_cursor
    query_string::aws_byte_cursor
    path_and_query::aws_byte_cursor
end

aws_uri() = aws_uri(0, C_NULL, aws_byte_buf(), aws_byte_cursor(), aws_byte_cursor(), aws_byte_cursor(), aws_byte_cursor(), aws_byte_cursor(), aws_byte_cursor(), 0, aws_byte_cursor(), aws_byte_cursor(), aws_byte_cursor())

function aws_uri_init_parse(uri, allocator, uri_str)
    ccall((:aws_uri_init_parse, libawscrt), Cint, (Ref{aws_uri}, Ptr{aws_allocator}, Ref{aws_byte_cursor}), uri, allocator, uri_str)
end

function aws_uri_clean_up(uri)
    ccall((:aws_uri_clean_up, libawscrt), Cvoid, (Ref{aws_uri},), uri)
end

mutable struct RequestContext
    allocator::Ptr{aws_allocator}
    completed::Threads.Event
    error::Union{Nothing, Exception}
    request_method::String
    request_uri::aws_uri
    request_headers::Any # Nothing or iterable of string pairs
    request_body::Any
    status_code::Int
    response_headers::Headers
    response_body::Vector{UInt8}
end

const aws_event_loop_group = Cvoid

function aws_event_loop_group_new_default(alloc, max_threads, shutdown_options)
    ccall((:aws_event_loop_group_new_default, libawscrt), Ptr{aws_event_loop_group}, (Ptr{aws_allocator}, UInt16, Ptr{Cvoid}), alloc, max_threads, shutdown_options)
end

const aws_shutdown_callback_options = Cvoid

mutable struct aws_host_resolver_default_options
    max_entries::Csize_t
    el_group::Ptr{aws_event_loop_group}
    shutdown_options::Ptr{aws_shutdown_callback_options}
    system_clock_override_fn::Ptr{Cvoid}
end

const aws_host_resolver = Cvoid

function aws_host_resolver_new_default(allocator, options)
    ccall((:aws_host_resolver_new_default, libawscrt), Ptr{aws_host_resolver}, (Ptr{aws_allocator}, Ref{aws_host_resolver_default_options}), allocator, options)
end

struct aws_client_bootstrap_options
    event_loop_group::Ptr{aws_event_loop_group}
    host_resolver::Ptr{aws_host_resolver}
    host_resolution_config::Ptr{Cvoid} # Ptr{aws_host_resolution_config}
    on_shutdown_complete::Ptr{Cvoid}
    user_data::Ptr{Cvoid}
end

const aws_client_bootstrap = Cvoid

function aws_client_bootstrap_new(allocator, options)
    ccall((:aws_client_bootstrap_new, libawscrt), Ptr{aws_client_bootstrap}, (Ptr{aws_allocator}, Ref{aws_client_bootstrap_options}), allocator, options)
end

@enum aws_socket_type::UInt32 begin
    AWS_SOCKET_STREAM = 0
    AWS_SOCKET_DGRAM = 1
end

@enum aws_socket_domain::UInt32 begin
    AWS_SOCKET_IPV4 = 0
    AWS_SOCKET_IPV6 = 1
    AWS_SOCKET_LOCAL = 2
    AWS_SOCKET_VSOCK = 3
end

mutable struct aws_socket_options
    type::aws_socket_type
    domain::aws_socket_domain
    connect_timeout_ms::UInt32
    keep_alive_interval_sec::UInt16
    keep_alive_timeout_sec::UInt16
    keep_alive_max_failed_probes::UInt16
    keepalive::Bool
end

struct aws_string
    allocator::Ptr{aws_allocator}
    len::Csize_t
    bytes::NTuple{1, UInt8}
end

const aws_tls_ctx_options = Cvoid
const aws_tls_ctx = Cvoid

const aws_tls_connection_options = Cvoid

function aws_tls_connection_options_init_from_ctx(conn_options, ctx)
    ccall((:aws_tls_connection_options_init_from_ctx, libawscrt), Cvoid, (Ref{aws_tls_connection_options}, Ptr{aws_tls_ctx}), conn_options, ctx)
end

function aws_tls_client_ctx_new(alloc, options)
    ccall((:aws_tls_client_ctx_new, libawscrt), Ptr{aws_tls_ctx}, (Ptr{aws_allocator}, Ptr{aws_tls_ctx_options}), alloc, options)
end

function aws_tls_ctx_options_init_client_mtls_from_path(options, allocator, cert_path, pkey_path)
    ccall((:aws_tls_ctx_options_init_client_mtls_from_path, libawscrt), Cint, (Ptr{aws_tls_ctx_options}, Ptr{aws_allocator}, Ptr{Cchar}, Ptr{Cchar}), options, allocator, cert_path, pkey_path)
end

function aws_tls_ctx_options_init_client_mtls_from_system_path(options, allocator, cert_reg_path)
    ccall((:aws_tls_ctx_options_init_client_mtls_from_system_path, libawscrt), Cint, (Ptr{aws_tls_ctx_options}, Ptr{aws_allocator}, Ptr{Cchar}), options, allocator, cert_reg_path)
end

function aws_tls_ctx_options_override_default_trust_store_from_path(options, ca_path, ca_file)
    ccall((:aws_tls_ctx_options_override_default_trust_store_from_path, libawscrt), Cint, (Ptr{aws_tls_ctx_options}, Ptr{Cchar}, Ptr{Cchar}), options, ca_path, ca_file)
end

function aws_tls_ctx_options_init_default_client(options, allocator)
    ccall((:aws_tls_ctx_options_init_default_client, libawscrt), Cvoid, (Ptr{aws_tls_ctx_options}, Ptr{aws_allocator}), options, allocator)
end

function aws_tls_ctx_options_set_alpn_list(options, alpn_list)
    ccall((:aws_tls_ctx_options_set_alpn_list, libawscrt), Cint, (Ptr{aws_tls_ctx_options}, Ptr{Cchar}), options, alpn_list)
end

function aws_tls_ctx_options_set_verify_peer(options, verify_peer)
    ccall((:aws_tls_ctx_options_set_verify_peer, libawscrt), Cvoid, (Ptr{aws_tls_ctx_options}, Bool), options, verify_peer)
end

function aws_tls_connection_options_set_server_name(conn_options, allocator, server_name)
    ccall((:aws_tls_connection_options_set_server_name, libawscrt), Cint, (Ptr{aws_tls_connection_options}, Ptr{aws_allocator}, Ref{aws_byte_cursor}), conn_options, allocator, server_name)
end

function aws_tls_connection_options_clean_up(connection_options)
    ccall((:aws_tls_connection_options_clean_up, libawscrt), Cvoid, (Ref{aws_tls_connection_options},), connection_options)
end

function aws_tls_ctx_release(ctx)
    ccall((:aws_tls_ctx_release, libawscrt), Cvoid, (Ptr{aws_tls_ctx},), ctx)
end

function aws_tls_ctx_options_clean_up(options)
    ccall((:aws_tls_ctx_options_clean_up, libawscrt), Cvoid, (Ptr{aws_tls_ctx_options},), options)
end

mutable struct aws_http_connection_manager_options
    bootstrap::Ptr{aws_client_bootstrap}
    initial_window_size::Csize_t
    socket_options::aws_socket_options
    tls_connection_options::Ptr{aws_tls_connection_options}
    http2_prior_knowledge::Bool
    monitoring_options::Ptr{Cvoid} # Ptr{aws_http_connection_monitoring_options}
    host::aws_byte_cursor
    port::UInt16
    initial_settings_array::Ptr{Cvoid} # Ptr{aws_http2_setting}
    num_initial_settings::Csize_t
    max_closed_streams::Csize_t
    http2_conn_manual_window_management::Bool
    proxy_options::Ptr{Cvoid} # Ptr{aws_http_proxy_options}
    proxy_ev_settings::Ptr{Cvoid} # Ptr{proxy_env_var_settings}
    max_connections::Csize_t
    shutdown_complete_user_data::Ptr{Cvoid}
    shutdown_complete_callback::Ptr{Cvoid}
    enable_read_back_pressure::Bool
    max_connection_idle_in_milliseconds::UInt64
end

function aws_http_connection_manager_options(
    bootstrap::Ptr{aws_client_bootstrap},
    socket_options::aws_socket_options,
    tls_options::Ptr{aws_tls_connection_options},
    host_name::aws_byte_cursor,
    port,
    max_connections,
    max_connection_idle_in_milliseconds
)
    return aws_http_connection_manager_options(
        bootstrap,
        typemax(Csize_t),
        socket_options,
        tls_options,
        false,
        C_NULL, # monitoring_options
        host_name,
        port % UInt16,
        C_NULL,
        0,
        0,
        false,
        C_NULL, # proxy_options
        C_NULL, # proxy_ev_settings
        max_connections,
        C_NULL,
        C_NULL,
        false,
        max_connection_idle_in_milliseconds,
    )
end

const aws_http_connection_manager = Cvoid

function aws_http_connection_manager_new(allocator, options)
    ccall((:aws_http_connection_manager_new, libawscrt), Ptr{aws_http_connection_manager}, (Ptr{aws_allocator}, Ref{aws_http_connection_manager_options}), allocator, options)
end

function aws_http_connection_manager_acquire_connection(manager, callback, user_data)
    ccall((:aws_http_connection_manager_acquire_connection, libawscrt), Cvoid, (Ptr{aws_http_connection_manager}, Ptr{Cvoid}, Ref{RequestContext}), manager, callback, user_data)
end

mutable struct aws_http_client_connection_options
    self_size::Csize_t #
    allocator::Ptr{aws_allocator} #
    bootstrap::Ptr{aws_client_bootstrap} #
    host_name::aws_byte_cursor #
    port::UInt16 #
    socket_options::aws_socket_options
    tls_options::Ptr{aws_tls_connection_options}
    proxy_options::Ptr{Cvoid} # Ptr{aws_http_proxy_options}
    proxy_ev_settings::Ptr{Cvoid} # Ptr{proxy_env_var_settings}
    monitoring_options::Ptr{Cvoid} # Ptr{aws_http_connection_monitoring_options}
    manual_window_management::Bool
    initial_window_size::Csize_t
    user_data::RequestContext
    on_setup::Ptr{Cvoid} #
    on_shutdown::Ptr{Cvoid} #
    prior_knowledge_http2::Bool
    alpn_string_map::Ptr{Cvoid} # Ptr{aws_hash_table}
    http1_options::Ptr{Cvoid} # Ptr{aws_http1_connection_options}
    http2_options::Ptr{Cvoid} # Ptr{aws_http2_connection_options}
    requested_event_loop::Ptr{Cvoid} # Ptr{aws_event_loop_group}
    host_resolution_config::Ptr{Cvoid} # Ptr{aws_host_resolution_config}
end

function aws_http_client_connection_options(
    alloc::Ptr{aws_allocator},
    bootstrap::Ptr{aws_client_bootstrap},
    host_name::aws_byte_cursor,
    port,
    socket_options::aws_socket_options,
    tls_options::Ptr{aws_tls_connection_options},
    ctx::RequestContext
)
return aws_http_client_connection_options(
    1,
    alloc,
    bootstrap,
    host_name,
    port % UInt16,
    socket_options,
    tls_options,
    C_NULL,
    C_NULL,
    C_NULL,
    false,
    typemax(Csize_t),
    ctx,
    on_setup[],
    on_shutdown[],
    false,
    C_NULL,
    C_NULL,
    C_NULL,
    C_NULL,
    C_NULL,
)
end

const aws_http_stream = Cvoid
const aws_http_connection = Cvoid

@enum aws_http_version::UInt32 begin
    AWS_HTTP_VERSION_UNKNOWN = 0
    AWS_HTTP_VERSION_1_0 = 1
    AWS_HTTP_VERSION_1_1 = 2
    AWS_HTTP_VERSION_2 = 3
    AWS_HTTP_VERSION_COUNT = 4
end

function aws_http_connection_get_version(connection)
    ccall((:aws_http_connection_get_version, libawscrt), aws_http_version, (Ptr{aws_http_connection},), connection)
end

function aws_http_stream_release(stream)
    ccall((:aws_http_stream_release, libawscrt), Cvoid, (Ptr{aws_http_stream},), stream)
end

const aws_http_message = Cvoid

function aws_http2_message_new_request(allocator)
    ccall((:aws_http2_message_new_request, libawscrt), Ptr{aws_http_message}, (Ptr{aws_allocator},), allocator)
end

function aws_http_message_new_request(allocator)
    ccall((:aws_http_message_new_request, libawscrt), Ptr{aws_http_message}, (Ptr{aws_allocator},), allocator)
end

@enum aws_http_header_block::UInt32 begin
    AWS_HTTP_HEADER_BLOCK_MAIN = 0
    AWS_HTTP_HEADER_BLOCK_INFORMATIONAL = 1
    AWS_HTTP_HEADER_BLOCK_TRAILING = 2
end

@enum aws_http_header_compression::UInt32 begin
    AWS_HTTP_HEADER_COMPRESSION_USE_CACHE = 0
    AWS_HTTP_HEADER_COMPRESSION_NO_CACHE = 1
    AWS_HTTP_HEADER_COMPRESSION_NO_FORWARD_CACHE = 2
end

struct aws_http_header
    name::aws_byte_cursor
    value::aws_byte_cursor
    compression::aws_http_header_compression
end

function aws_http_stream_get_incoming_response_status(stream, out_status)
    ccall((:aws_http_stream_get_incoming_response_status, libawscrt), Cint, (Ptr{aws_http_stream}, Ptr{Cint}), stream, out_status)
end

function aws_http_message_set_request_method(request_message, method)
    ccall((:aws_http_message_set_request_method, libawscrt), Cint, (Ptr{aws_http_message}, aws_byte_cursor), request_message, method)
end

function aws_http_message_set_request_path(request_message, path)
    ccall((:aws_http_message_set_request_path, libawscrt), Cint, (Ptr{aws_http_message}, aws_byte_cursor), request_message, path)
end

const aws_http_headers = Cvoid

function aws_http_message_get_headers(message)
    ccall((:aws_http_message_get_headers, libawscrt), Ptr{aws_http_headers}, (Ptr{aws_http_message},), message)
end

function aws_http2_headers_set_request_scheme(h2_headers, scheme)
    ccall((:aws_http2_headers_set_request_scheme, libawscrt), Cint, (Ptr{aws_http_headers}, aws_byte_cursor), h2_headers, scheme)
end

function aws_http2_headers_set_request_authority(h2_headers, authority)
    ccall((:aws_http2_headers_set_request_authority, libawscrt), Cint, (Ptr{aws_http_headers}, aws_byte_cursor), h2_headers, authority)
end

function aws_http_message_add_header(message, header)
    ccall((:aws_http_message_add_header, libawscrt), Cint, (Ptr{aws_http_message}, aws_http_header), message, header)
end

function aws_http_message_set_body_stream(message, body_stream)
    ccall((:aws_http_message_set_body_stream, libawscrt), Cvoid, (Ptr{aws_http_message}, Ptr{aws_input_stream}), message, body_stream)
end

mutable struct aws_http_make_request_options
    self_size::Csize_t
    request::Ptr{aws_http_message}
    user_data::RequestContext
    on_response_headers::Ptr{Cvoid}
    on_response_header_block_done::Ptr{Cvoid}
    on_response_body::Ptr{Cvoid}
    on_complete::Ptr{Cvoid}
end

function aws_http_make_request_options(request::Ptr{aws_http_message}, ctx::RequestContext)
    return aws_http_make_request_options(
        1,
        request,
        ctx,
        on_response_headers[],
        on_response_header_block_done[],
        on_response_body[],
        on_complete[],
    )
end

function aws_http_connection_make_request(client_connection, options)
    ccall((:aws_http_connection_make_request, libawscrt), Ptr{aws_http_stream}, (Ptr{aws_http_connection}, Ref{aws_http_make_request_options}), client_connection, options)
end

function aws_http_stream_activate(stream)
    ccall((:aws_http_stream_activate, libawscrt), Cint, (Ptr{aws_http_stream},), stream)
end

function aws_http_connection_release(connection)
    ccall((:aws_http_connection_release, libawscrt), Cvoid, (Ptr{aws_http_connection},), connection)
end

function aws_http_client_connect(options)
    ccall((:aws_http_client_connect, libawscrt), Cint, (Ref{aws_http_client_connection_options},), options)
end

function aws_http_message_release(message)
    ccall((:aws_http_message_release, libawscrt), Ptr{aws_http_message}, (Ptr{aws_http_message},), message)
end
