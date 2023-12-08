import "math"

rule php_proxy
{
	meta:
		description = "Detect the risk of malicious file (phpwebshell)  Rule 59"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "  $result = file_get_contents($url, false, $context);" fullword ascii
		$s2 = "  //$postdata = http_build_query($data);" fullword ascii
		$s3 = "POST {$path} HTTP/1.1" fullword ascii
		$s4 = "Host: {$host}:$port" fullword ascii
		$s5 = "    // split the result header from the content" fullword ascii
		$s6 = "HEADER;" fullword ascii
		$s7 = "Content-Length: {$length}" fullword ascii
		$s8 = "    $post_arg = file_get_contents(\"php://input\");" fullword ascii
		$s9 = "if ($_SERVER['REQUEST_METHOD'] === 'GET') {" fullword ascii
		$s10 = "function my_socket_post($url, $data)" fullword ascii
		$s11 = "function post($url, $data)" fullword ascii
		$s12 = "        curl_exec($ch);" fullword ascii
		$s13 = "    $RemoteServer = $_POST['Remoteserver'];" fullword ascii
		$s14 = "ini_set(\"display_errors\", \"On\");" fullword ascii
		$s15 = "  $opts = array('http' =>" fullword ascii
		$s16 = "    $fp = fsockopen($host, $port, $errno, $errstr, 3);" fullword ascii
		$s17 = "             'header' => 'Content-type: application/x-www-form-urlencoded'," fullword ascii
		$s18 = "        die (\"Error: Only HTTP request are supported !\");" fullword ascii
		$s19 = "Content-Type: application/x-www-form-urlencoded\\r\\n" fullword ascii
		$s20 = "        curl_setopt($ch, CURLOPT_POSTFIELDS, $post_arg);" fullword ascii

	condition:
		uint16(0)==0x3f3c and filesize <7KB and 8 of them
}
