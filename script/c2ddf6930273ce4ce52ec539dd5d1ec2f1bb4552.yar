rule SUSP_HTML_WASM_Smuggling
{
	meta:
		description = "Presence of Base64 JavaScript blob loading WASM"
		author = "delivr.to"
		date = "2024-02-28"
		score = 70
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$wasm = "WebAssembly.Module" base64
		$int = "WebAssembly.Instance" base64
		$inst = "WebAssembly.instantiate" base64

	condition:
		all of them
}
