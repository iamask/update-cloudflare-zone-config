terraform {
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.0"

    }

  }
}

variable "CLOUDFLARE_API_TOKEN" {
  description = "Cloudflare API token"
}

variable "CLOUDFLARE_ZONE_ID" {
  description = "Cloudflare zone"
}


provider "cloudflare" {
  api_token = var.CLOUDFLARE_API_TOKEN
}

resource "cloudflare_record" "www" {
  zone_id = var.CLOUDFLARE_ZONE_ID
  name    = "www"
  value   = "203.0.113.100"
  type    = "A"
  proxied = true
}

resource "cloudflare_record" "a" {
  zone_id = var.CLOUDFLARE_ZONE_ID
  name    = "aa"
  value   = "1.0.23.100"
  type    = "A"
  proxied = true
}

resource "cloudflare_record" "aa" {
  zone_id = var.CLOUDFLARE_ZONE_ID
  name    = "aa"
  value   = "200.0.23.100"
  type    = "A"
  proxied = true
}


resource "cloudflare_zone_settings_override" "tf-zxc-co-in-settings" {
  zone_id = var.CLOUDFLARE_ZONE_ID

  settings {
    tls_1_3                  = "on"
    automatic_https_rewrites = "on"
    ssl                      = "strict"
    brotli                   = "on"
    polish                   = "lossless"
    http2                    = "on"
    http3                    = "on"
    h2_prioritization        = "on"
    origin_max_http_version  = "2"
    always_use_https         = "on"
    early_hints              = "on"
    rocket_loader            = "on"
    ipv6                     = "on"
    min_tls_version          = "1.3"
    zero_rtt                 = "on"
    prefetch_preload         = "on"
    minify {
      css  = "on"
      html = "on"
      js   = "on"
    }

  }
}

# Configure a ruleset at the zone level for the "http_request_firewall_managed" phase
resource "cloudflare_ruleset" "zone_level_managed_waf" {
  zone_id     = var.CLOUDFLARE_ZONE_ID
  name        = "Managed WAF entry point ruleset"
  description = "Zone-level WAF Managed Rules config"
  kind        = "zone"
  phase       = "http_request_firewall_managed"

  # Execute Cloudflare Managed Ruleset
  rules {
    action = "execute"
    action_parameters {
      id      = "efb7b8c949ac4650a09736fc376e9aee"
      version = "latest"
    }
    expression  = "true"
    description = "ExecutE Cloudflare Managed Ruleset on my zone-level phase entry point ruleset"
    enabled     = true
  }

  # Execute Cloudflare OWASP Core Ruleset
  rules {
    action = "execute"
    action_parameters {
      id      = "4814384a9e5d4991b9815dcfc25d2f1f"
      version = "latest"
    }
    expression  = "true"
    description = "Execute Cloudflare OWASP Core Ruleset on my zone-level phase entry point ruleset"
    enabled     = true
  }
}


resource "cloudflare_ruleset" "zone_rl" {
  zone_id     = var.CLOUDFLARE_ZONE_ID
  name        = "Phase entry point ruleset for RL"
  description = "RL"
  kind        = "zone"
  phase       = "http_ratelimit"

  rules {
    action = "managed_challenge"
    ratelimit {
      characteristics     = ["cf.unique_visitor_id", "cf.colo.id"]
      period              = 10
      requests_per_period = 20
      mitigation_timeout  = 0
    }
    expression  = "(http.host eq \"staging.zone.com\")"
    description = "RL baseline 1 (Burst)- 20/10sec "
    enabled     = true
  }

  rules {
    action = "managed_challenge"
    ratelimit {
      characteristics     = ["cf.unique_visitor_id", "cf.colo.id"]
      period              = 60
      requests_per_period = 100
      mitigation_timeout  = 0
    }
    expression  = "(http.host eq \"staging.zone.com\")"
    description = "RL baseline 2 (Burst)- 100/60sec"
    enabled     = true
  }


  rules {
    action = "managed_challenge"
    ratelimit {
      characteristics     = ["cf.unique_visitor_id", "cf.colo.id"]
      period              = 600
      requests_per_period = 2000
      mitigation_timeout  = 0
    }
    expression  = "(http.host eq \"staging.zone.com\")"
    description = "RL baseline 3 (Slow and Low)- 2000/10Min"
    enabled     = true
  }

}







resource "cloudflare_ruleset" "zone_custom_firewall" {
  zone_id     = var.CLOUDFLARE_ZONE_ID
  name        = "Phase entry point ruleset for custom rules in zone tf.zxc.co.in"
  description = ""
  kind        = "zone"
  phase       = "http_request_firewall_custom"

  rules {
    action      = "block"
    expression  = "(not cf.edge.server_port in {80 443})"
    description = "Block ports other than 80 and 443"
    enabled     = true
  }

  rules {
    action      = "block"
    expression  = "(ip.geoip.country in {\"CN\" \"PK\" \"RU\" \"UA\"})"
    description = "Geo Block for POC"
    enabled     = true
  }

  rules {
    action      = "log"
    expression  = "(ip.src in $cf.anonymizer) or (ip.src in $cf.botnetcc) or (ip.src in $cf.malware) or (ip.src in $cf.open_proxies) or (ip.src in $cf.vpn)"
    description = "Log Managed IP list"
    enabled     = true
  }

  rules {
    action      = "block"
    expression  = "(cf.threat_score gt 80)"
    description = "Log IP Threatscore"
    enabled     = true
  }

  rules {
    action      = "block"
    expression  = "(cf.waf.score lt 20)"
    description = "WAF Attack score : Attack"
    enabled     = true
  }

  rules {
    action      = "managed_challenge"
    expression  = "(cf.waf.score gt 20 and cf.waf.score lt 50)"
    description = "WAF Attack score : Likely Attack"
    enabled     = true
  }

  rules {
    action      = "block"
    expression  = "(cf.bot_management.score eq 1)"
    description = "Bot Check : Automated"
    enabled     = true
  }

  rules {
    action      = "managed_challenge"
    expression  = "(cf.bot_management.score gt 1 and cf.bot_management.score lt 30)"
    description = "Bot Check : Likely Automated"
    enabled     = true
  }
}




resource "cloudflare_ruleset" "transform_modify_request_headers" {
  zone_id     = var.CLOUDFLARE_ZONE_ID
  name        = "Transform Rule performing HTTP request header modifications"
  description = ""
  kind        = "zone"
  phase       = "http_request_late_transform"

  rules {
    action = "rewrite"
    action_parameters {
      headers {
        name      = "X-Source"
        operation = "set"
        value     = "Cloudflare"
      }

    }
    expression  = "true"
    description = "Example HTTP Request Header Modification Rule"
    enabled     = true
  }
}


