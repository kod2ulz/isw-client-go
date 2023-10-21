-- name: LogApiRequest :one
insert into interswitch.api_calls (
  request_id, remote_ip, method, url, request
) values (
  @request_id, @remote_ip, @method, @url, @request
) returning *;

-- name: LogApiResponse :one
update interswitch.api_calls
set response_code = @response_code::int,
         response = @response,
     completed_at = now()
where
  request_id= @request_id
returning *;