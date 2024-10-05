dev:
    gleam run -m lustre/dev start

login:
    hurl --variable api_url=$API_URL hurls/login.hurl
