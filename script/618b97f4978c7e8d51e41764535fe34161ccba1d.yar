rule Lazarus_defaultdownpy_python
{
	meta:
		description = "Python downloader for Lazarus"
		author = "JPCERT/CC Incident Response Group"
		hash = "3b6a8d4c15f645d3c1a9f58fc8f4fd691cea26a54e5a251f445d4013e9057dd0"
		hash = "70db987e2545cbc3e22bac0503f89f46a441cc9f206d0aa41d66b54f511638d6"
		hash = "e93f2f24718711ddd7751b40cdfcd92814388a65015d1a1e8bc1b1885ada5fca"
		hash = "6a2893c44d9a7f3bcad492ea7dbcea90eb0107fd0c191913cd097b663f806a67"
		hash = "0046ad625564f42b9dd69f3479732b3e1aaf5ef3e365f4752006e703963dd3de"
		hash = "1c0f6ffc30b702c7b6aeee2b38ef749b8329554603082d3e179b37ff86371858"
		os = "windows"
		filetype = "script"

	strings:
		$enc1 = "d=base64.b64decode(t[8:])" ascii
		$enc2 = "k=i&7;c=chr(d[i]^ord(sk[k]))" ascii
		$enc3 = "exec(res)" ascii
		$enc4 = "data=base64.b64decode(temp[8:]);" ascii
		$enc5 = "k=i&7;c=chr(data[i]^ord(sk[k]))" ascii
		$dec1 = "base64.b64decode(host[10:] + host[:10]).decode()" ascii
		$dec2 = "subprocess.Popen([sys.executable, ap], creationflags=subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP)" ascii
		$dec3 = "subprocess.Popen(cmd,shell=_T,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE).communicate()" ascii
		$dec4 = "if ot==\"Darwin\":" ascii
		$dec5 = "subprocess.check_call([sys.executable, '-m', 'pip', 'install', " ascii
		$dec6 = "subprocess.check_call([sys.executable,'-m','pip','install'," ascii
		$dec7 = "subprocess.check_call([sys.executable,_M,_P,_L," ascii
		$dec8 = "subprocess.check_call([sys.executable,_m,_pp,_inl," ascii
		$dec9 = "ot = platform.system()" ascii
		$dec10 = "download_payload():" ascii
		$dec11 = "download_browse()" ascii
		$dec12 = "get_anydesk_path():" ascii
		$dec13 = "retrieve_web(self):" ascii
		$dec14 = "ssh_cmd(A,args):" ascii
		$dec15 = "ssh_upload(A,args)" ascii
		$dec16 = "win32process.GetWindowThreadProcessId(win32gui.GetForegroundWindow());return (pid[-1], psutil.Process(pid[-1]).name())" ascii
		$dec17 = "is_down(pyHook.GetKeyState(0x11)) or is_down(pyHook.GetKeyState(0xA2)) or is_down(pyHook.GetKeyState(0xA3))" ascii
		$dec18 = "sha256((str(getnode())+getuser()).encode()).digest().hex()" ascii
		$dec19 = "return{'uuid':A.uuid,'system':A.system,'release':A.release,'version':A.version,'hostname':A.hostname,'username':A.username}" ascii
		$dec20 = "{'ts':str(B),'type':sType,'hid':hn,'ss':'sys_info','cc':str(A.sys_info)}" ascii

	condition:
		3 of ($enc*) or 3 of ($dec*)
}
