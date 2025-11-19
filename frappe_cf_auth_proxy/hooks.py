app_name = "frappe_cf_auth_proxy"
app_title = "Cf Auth Proxy"
app_publisher = "Codevedas Inc."
app_description = "Auto login using Cloudflare JWT"
app_email = "nitesh@codevedas.com"
app_license = "mit"
before_request = ["frappe_cf_auth_proxy.auth.ensure_user"]