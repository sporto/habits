POST {{api_url}}/auth/v1/token?grant_type=password
apikey: {{api_public_key}}
Authorization: Bearer {{api_public_key}}
Content-Type: application/json
{
    "email": "{{user_email}}",
    "password": "{{user_password}}"
}
