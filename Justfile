build:
    npx vite build

dev:
    npx vite

tw:
    npx tailwindcss -i ./src/app_input.css -o ./src/app.css --watch

login:
    hurl -v \
    --variable api_url=$API_URL \
    --variable api_public_key=$API_PUBLIC_KEY \
    --variable user_email=$USER_EMAIL \
    --variable user_password=$USER_PASSWORD \
    hurls/login.hurl
