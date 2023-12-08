import "math"

rule aspx_proxy
{
	meta:
		description = "Detect the risk of malicious file (aspxwebshell)  Rule 60"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "        HttpWebRequest newrequest = (HttpWebRequest)WebRequest.Create(url+\"?\"+post_arg);" fullword ascii
		$s2 = "        using (StreamReader reader = new StreamReader(newresponse.GetResponseStream()))" fullword ascii
		$s3 = "    if (Request.HttpMethod == \"GET\")" fullword ascii
		$s4 = "        {" fullword ascii
		$s5 = "        string url = Remoteserver + Endpoint;" fullword ascii
		$s6 = "        }" fullword ascii
		$s7 = "<%@ Page Language=\"C#\" Debug=\"true\"%>" fullword ascii
		$s8 = "        WebResponse newresponse = newrequest.GetResponse();" fullword ascii
		$s9 = "            requestStream = newrequest.GetRequestStream();" fullword ascii
		$s10 = "        int cont = Request.ContentLength;" fullword ascii
		$s11 = "        String post_arg = Encoding.UTF8.GetString(buffer, 0, cont);" fullword ascii
		$s12 = "        newrequest.Method = \"POST\";" fullword ascii
		$s13 = "        System.IO.Stream s = Request.InputStream;" fullword ascii
		$s14 = "            System.IO.Stream requestStream = null;" fullword ascii
		$s15 = "        s.Read(buffer, 0, cont);" fullword ascii
		$s16 = "        string Remoteserver = Request.Form[\"Remoteserver\"]; " fullword ascii
		$s17 = "            backMsg = reader.ReadToEnd();" fullword ascii

	condition:
		uint16(0)==0xbbef and filesize <4KB and 8 of them
}
