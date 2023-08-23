module ServiceIO

const libawscrt = "/Users/quinnj/aws-crt/lib/libaws-c-http"

const Header = Pair{String, String}
const Headers = Vector{Header}

const EMPTY_BODY = UInt8[]

include("c.jl")

const ALLOCATOR = Ref{Ptr{Cvoid}}(C_NULL)
const EVENT_LOOP_GROUP = Ref{Ptr{Cvoid}}(C_NULL)
const HOST_RESOLVER = Ref{Ptr{Cvoid}}(C_NULL)
const CLIENT_BOOTSTRAP = Ref{Ptr{Cvoid}}(C_NULL)
const DEFAULT_SOCKET_OPTIONS = aws_socket_options(
    AWS_SOCKET_STREAM, # socket type
    AWS_SOCKET_IPV4, # socket domain
    3000, # connect_timeout_ms
    0, # keep_alive_interval_sec
    0, # keep_alive_timeout_sec
    0, # keep_alive_max_failed_probes
    false # keepalive
)
const LOGGER = Ref{Ptr{Cvoid}}(C_NULL)
const CONNECTION_MANAGERS = Dict{String, Ptr{aws_http_connection_manager}}()

include("http.jl")

function __init__()
    # populate default allocator
    ALLOCATOR[] = aws_default_allocator()
    @assert ALLOCATOR[] != C_NULL
    # populate default event loop group; 0 means one event loop per non-hypterthread core
    EVENT_LOOP_GROUP[] = aws_event_loop_group_new_default(ALLOCATOR[], 0, C_NULL)
    @assert EVENT_LOOP_GROUP[] != C_NULL
    # populate default host resolver
    resolver_options = aws_host_resolver_default_options(8, EVENT_LOOP_GROUP[], C_NULL, C_NULL)
    HOST_RESOLVER[] = aws_host_resolver_new_default(ALLOCATOR[], resolver_options)
    @assert HOST_RESOLVER[] != C_NULL
    # populate default client bootstrap w/ event loop, host resolver, and allocator
    bootstrap_options = aws_client_bootstrap_options(EVENT_LOOP_GROUP[], HOST_RESOLVER[], C_NULL, C_NULL, C_NULL)
    CLIENT_BOOTSTRAP[] = aws_client_bootstrap_new(ALLOCATOR[], bootstrap_options)
    @assert CLIENT_BOOTSTRAP[] != C_NULL
    # initialize logger
    LOGGER[] = aws_mem_acquire(ALLOCATOR[], 64)
    log_options = aws_logger_standard_options(0, Libc.FILE(Libc.RawFD(1), "r+"))
    aws_logger_init_standard(LOGGER[], ALLOCATOR[], log_options) != 0 && aws_throw_error()
    aws_logger_set(LOGGER[])
    # intialize http library
    aws_http_library_init(ALLOCATOR[])
    on_shutdown[] = @cfunction(c_on_shutdown, Cvoid, (Ptr{Cvoid}, Cint, Ptr{Cvoid}))
    on_setup[] = @cfunction(c_on_setup, Cvoid, (Ptr{Cvoid}, Cint, Ptr{Cvoid}))
    on_response_headers[] = @cfunction(c_on_response_headers, Cint, (Ptr{Cvoid}, Cint, Ptr{Cvoid}, Csize_t, Ptr{Cvoid}))
    on_response_header_block_done[] = @cfunction(c_on_response_header_block_done, Cint, (Ptr{Cvoid}, Cint, Ptr{Cvoid}))
    on_response_body[] = @cfunction(c_on_response_body, Cint, (Ptr{Cvoid}, Ptr{aws_byte_cursor}, Ptr{Cvoid}))
    on_complete[] = @cfunction(c_on_complete, Cvoid, (Ptr{Cvoid}, Cint, Ptr{Cvoid}))
    return
end

end
