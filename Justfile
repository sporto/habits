dev:
    gleam run -m lustre/dev start

login:
    hurl -v \
    --variable api_url=$API_URL \
    --variable api_public_key=$API_PUBLIC_KEY \
    --variable user_email=$USER_EMAIL \
    --variable user_password=$USER_PASSWORD \
    hurls/login.hurl
