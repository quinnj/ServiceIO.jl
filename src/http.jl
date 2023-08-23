const on_setup = Ref{Ptr{Cvoid}}(C_NULL)

function c_on_setup(conn, error_code, user_data)
    println("on setup")
    ctx = unsafe_pointer_to_objref(user_data)
    if error_code != 0
        ctx.error = CapturedException(aws_error(), Base.backtrace())
        Threads.notify(ctx.completed)
        return
    end
    # build request
    protocol_version = aws_http_connection_get_version(conn)
    request = protocol_version == AWS_HTTP_VERSION_2 ?
          aws_http2_message_new_request(ctx.allocator) :
          aws_http_message_new_request(ctx.allocator)
    if request == C_NULL
        ctx.error = CapturedException(aws_error(), Base.backtrace())
        Threads.notify(ctx.completed)
        return
    end
    # set method
    aws_http_message_set_request_method(request, aws_byte_cursor_from_c_str(ctx.request_method))
    # set path
    if ctx.request_uri.path_and_query.len != 0
        aws_http_message_set_request_path(request, ctx.request_uri.path_and_query)
    else
        aws_http_message_set_request_path(request, aws_byte_cursor_from_c_str("/"))
    end
    # set headers
    if protocol_version == AWS_HTTP_VERSION_2
        h2_headers = aws_http_message_get_headers(request)
        aws_http2_headers_set_request_scheme(h2_headers, ctx.request_uri.scheme)
        aws_http2_headers_set_request_authority(h2_headers, ctx.request_uri.host_name)
    else
        host_header = aws_http_header(aws_byte_cursor_from_c_str("host"), ctx.request_uri.host_name, AWS_HTTP_HEADER_COMPRESSION_USE_CACHE)
        aws_http_message_add_header(request, host_header)
    end
    # accept header
    accept_header = aws_http_header(aws_byte_cursor_from_c_str("accept"), aws_byte_cursor_from_c_str("*/*"), AWS_HTTP_HEADER_COMPRESSION_USE_CACHE)
    aws_http_message_add_header(request, accept_header)
    # user-agent header
    user_agent_header = aws_http_header(aws_byte_cursor_from_c_str("user-agent"), aws_byte_cursor_from_c_str("ServiceIO.jl"), AWS_HTTP_HEADER_COMPRESSION_USE_CACHE)
    aws_http_message_add_header(request, user_agent_header)
    # user-provided headers
    if ctx.request_headers !== nothing
        for (k, v) in ctx.request_headers
            header = aws_http_header(aws_byte_cursor_from_c_str(string(k)), aws_byte_cursor_from_c_str(string(v)), AWS_HTTP_HEADER_COMPRESSION_USE_CACHE)
            aws_http_message_add_header(request, header)
        end
    end
    # set body
    if ctx.request_body !== nothing
        if ctx.request_body isa AbstractString
            cbody = aws_byte_cursor_from_c_str(ctx.request_body)
            input_stream = aws_input_stream_new_from_cursor(ctx.allocator, cbody)
        elseif ctx.request_body isa AbstractVector{UInt8}
            cbody = aws_byte_cursor(sizeof(ctx.request_body), pointer(ctx.request_body))
            input_stream = aws_input_stream_new_from_cursor(ctx.allocator, cbody)
        elseif ctx.request_body isa IOStream
            input_stream = aws_input_stream_new_from_open_file(ctx.allocator, Libc.FILE(ctx.request_body))
        else
            throw(ArgumentError("request body must be a string, vector of UInt8, or IOStream"))
        end
        data_len_ref = Ref(0)
        aws_input_stream_get_length(input_stream, data_len_ref) != 0 && aws_throw_error()
        data_len = data_len_ref[]
        if data_len > 0
            content_length_header = aws_http_header(aws_byte_cursor_from_c_str("content-length"), aws_byte_cursor_from_c_str(string(data_len)), AWS_HTTP_HEADER_COMPRESSION_USE_CACHE)
            aws_http_message_add_header(request, content_length_header)
            aws_http_message_set_body_stream(request, input_stream)
        else
            aws_input_stream_destroy(input_stream)
        end
    end

    final_request = aws_http_make_request_options(request, ctx)
    stream = aws_http_connection_make_request(conn, final_request)
    if stream == C_NULL
        ctx.error = CapturedException(aws_error(), Base.backtrace())
        Threads.notify(ctx.completed)
        return
    end
    aws_http_message_release(request)
    aws_http_stream_activate(stream)
    aws_http_connection_release(conn)
    return
end

const on_shutdown = Ref{Ptr{Cvoid}}(C_NULL)

function c_on_shutdown(conn, error_code, user_data)
    ctx = unsafe_pointer_to_objref(user_data)
    if error_code != 0
        ctx.error = CapturedException(aws_error(), Base.backtrace())
    end
    Threads.notify(ctx.completed)
    return
end

const on_response_headers = Ref{Ptr{Cvoid}}(C_NULL)

function c_on_response_headers(stream, header_block, header_array, num_headers, user_data)
    ctx = unsafe_pointer_to_objref(user_data)
    headers = unsafe_wrap(Array, Ptr{aws_http_header}(header_array), num_headers)
    for header in headers
        push!(ctx.response_headers, unsafe_string(header.name.ptr, header.name.len) => unsafe_string(header.value.ptr, header.value.len))
    end
    return Cint(0)
end

const on_response_header_block_done = Ref{Ptr{Cvoid}}(C_NULL)

function c_on_response_header_block_done(stream, header_block, user_data)
    ctx = unsafe_pointer_to_objref(user_data)
    ptr = Ptr{UInt8}(user_data) + fieldoffset(RequestContext, Base.fieldindex(RequestContext, :status_code))
    aws_http_stream_get_incoming_response_status(stream, ptr)
    ctx.status_code = unsafe_load(ptr)
    return Cint(0)
end

const on_response_body = Ref{Ptr{Cvoid}}(C_NULL)

function c_on_response_body(stream, data::Ptr{aws_byte_cursor}, user_data)
    ctx = unsafe_pointer_to_objref(user_data)
    bc = unsafe_load(data)
    x = unsafe_wrap(Array, bc.ptr, bc.len)
    append!(ctx.response_body, x)
    return Cint(0)
end

const on_complete = Ref{Ptr{Cvoid}}(C_NULL)

function c_on_complete(stream, error_code, user_data)
    ctx = unsafe_pointer_to_objref(user_data)
    aws_http_stream_release(stream)
    Threads.notify(ctx.completed)
    return
end

struct Response
    status_code::Int
    headers::Headers
    body::Vector{UInt8}
end

# main entrypoint for making an HTTP request
# can provide method, url, headers, body, along with various keyword arguments
function request(method, url, headers=nothing, body::Union{AbstractString, AbstractVector{UInt8}, IOStream, Nothing}=nothing;
    allocator=ALLOCATOR[],
    bootstrap=CLIENT_BOOTSTRAP[],
    # socket options
    socket_domain=:ipv4,
    connect_timeout_ms::Integer=3000,
    keep_alive_interval_sec::Integer=0,
    keep_alive_timeout_sec::Integer=0,
    keep_alive_max_failed_probes::Integer=0,
    keepalive::Bool=false,
    # tls options
    ssl_cert=nothing,
    ssl_key=nothing,
    ssl_capath=nothing,
    ssl_cacert=nothing,
    ssl_insecure=false,
    ssl_alpn_list="h2;http/1.1",
    max_connections::Integer=512,
    max_connection_idle_in_milliseconds::Integer=60000,
    verbose=0, # 1-6
    kw...)
    # enable logging
    if verbose > 0
        aws_logger_set_log_level(LOGGER[], aws_log_level(verbose))
    end
    # parse url
    uri_cursor = aws_byte_cursor_from_c_str(url)
    uri = aws_uri()
    aws_uri_init_parse(uri, allocator, uri_cursor) != 0 && aws_error()
    # create a request context for shared state that we pass between all the callbacks
    ctx = RequestContext(allocator, Threads.Event(), nothing, method, uri, headers, body, 0, Headers(), UInt8[])

    # if port is given explicitly then use it, otherwise use 80 for http and 443 for https
    port = UInt16(uri.port != 0 ? uri.port : aws_byte_cursor_eq_c_str_ignore_case(uri.scheme, "http") ? 80 : 443)

    socket_options = DEFAULT_SOCKET_OPTIONS
    # if any non-default socket options are given, create a new socket options object
    if socket_domain != :ipv4 ||
        connect_timeout_ms != 3000 ||
        keep_alive_interval_sec != 0 ||
        keep_alive_timeout_sec != 0 ||
        keep_alive_max_failed_probes != 0 ||
        keepalive != false
        socket_options = aws_socket_options(
            AWS_SOCKET_STREAM,
            socket_domain == :ipv4 ? AWS_SOCKET_IPV4 : AWS_SOCKET_IPV6,
            connect_timeout_ms,
            keep_alive_interval_sec,
            keep_alive_timeout_sec,
            keep_alive_max_failed_probes,
            keepalive
        )
    end
    # figure out tls_options
    tls_options = C_NULL
    if port == 443
        tls_options = aws_mem_acquire(allocator, 64)
        tls_ctx_options = aws_mem_acquire(allocator, 512)
        if ssl_cert !== nothing && ssl_key !== nothing
            aws_tls_ctx_options_init_client_mtls_from_path(tls_ctx_options, allocator, ssl_cert, ssl_key) != 0 && aws_throw_error()
        elseif Sys.iswindows() && ssl_cert !== nothing && ssl_key === nothing
            aws_tls_ctx_options_init_client_mtls_from_system_path(tls_ctx_options, allocator, ssl_cert) != 0 && aws_throw_error()
        else
            aws_tls_ctx_options_init_default_client(tls_ctx_options, allocator)
        end
        if ssl_capath !== nothing && ssl_cacert !== nothing
            aws_tls_ctx_options_override_default_trust_store_from_path(tls_ctx_options, ssl_capath, ssl_cacert) != 0 && aws_throw_error()
        end
        if ssl_insecure
            aws_tls_ctx_options_set_verify_peer(tls_ctx_options, false)
        end
        aws_tls_ctx_options_set_alpn_list(tls_ctx_options, ssl_alpn_list) != 0 && aws_throw_error()
        tls_ctx = aws_tls_client_ctx_new(allocator, tls_ctx_options)
        tls_ctx == C_NULL && aws_throw_error()
        aws_tls_connection_options_init_from_ctx(tls_options, tls_ctx)
        aws_tls_connection_options_set_server_name(tls_options, allocator, uri.host_name) != 0 && aws_throw_error()
    end

    connection_manager = get!(CONNECTION_MANAGERS, unsafe_string(uri.host_name.ptr, uri.host_name.len)) do
        http_connection_manager_options = aws_http_connection_manager_options(
            bootstrap,
            socket_options,
            tls_options,
            uri.host_name,
            port,
            max_connections,
            max_connection_idle_in_milliseconds
        )
        cm = aws_http_connection_manager_new(allocator, http_connection_manager_options)
        cm == C_NULL && aws_throw_error()
        return cm
    end
    # initiate the remote connection, which will then kick off the cascade of callbacks
    println("acquiring connection")
    aws_http_connection_manager_acquire_connection(connection_manager, on_setup[], ctx)
    # eventually, one of our callbacks will notify ctx.completed, at which point we can return
    wait(ctx.completed)
    ctx.error !== nothing && throw(ctx.error)
    # cleanup tls_options
    if tls_options != C_NULL
        aws_tls_connection_options_clean_up(tls_options)
        aws_tls_ctx_release(tls_ctx)
        aws_tls_ctx_options_clean_up(tls_ctx_options)
    end
    # cleanup uri
    aws_uri_clean_up(uri)
    # cleanu logging
    if verbose > 0
        aws_logger_set_log_level(LOGGER[], aws_log_level(0))
    end

    return Response(ctx.status_code, ctx.response_headers, ctx.response_body)
end
