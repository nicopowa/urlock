class URLock {

	constructor() {

		this.ui = Object.entries({
			wrp: "wrp",
			row: "row",
			pwd: "pwd",
			cwd: "cwd",
			rev: "rev",
			btn: "btn",
			ttl: "ttl",
			txt: "txt",
			nnm: "nnm",
			siz: "siz",
			act: "act",
			fin: "fin"
		})
		.reduce(
			(acc, [k, v]) =>
				({
					...acc,
					[k]: document.querySelector("#" + v)
				}),
			{}
		);

		this.b64 = {
			alphabet: "base64url"
		};

		this.blb = {
			type: "text/plain"
		};

		this.timed = 0;
        
		this.dat = "";
		this.bin = null;

		const hsh = location.hash.replace(
			/^#/,
			""
		);

		this.dec = !!hsh;
        
		this.ui.wrp.className = this.dec ? "dec" : "enc";
		this.ui.btn.innerText = this.dec ? "unlock" : "share";

		this.ui.btn.onclick = () =>
			this.run();

		// passive
		this.ui.pwd.addEventListener(
			"keydown",
			e =>
				e.key === "Enter" && this.run()
		);

		this.ui.rev.addEventListener(
			"click",
			() =>
				[this.ui.rev, this.ui.pwd].forEach(el =>
					el.classList.toggle("show"))
		);

		this.ui.cwd.addEventListener(
			"click",
			() =>
				navigator.clipboard.writeText(this.ui.pwd.value)
				.then(() =>
					this.info(
						"copied",
						this.ui.cwd
					))
		);

		if(this.dec) {

			const spl = hsh.split(/\||%7C/);

			if(spl.length > 1)
				this.ui.ttl.value = decodeURIComponent(spl.shift());
			
			this.ui.ttl.disabled = true;

			this.dat = spl[0];
			
			this.ui.pwd.focus();
		
		}
		else {

			this.ui.fin.onchange = e =>
				e.target.files[0] && this.loadFile(e.target.files[0]);
            
			document.body.ondragover = e =>
				e.preventDefault();
            
			document.body.ondrop = e => {
 
				e.preventDefault();

				if(e.dataTransfer.files[0])
					this.loadFile(e.dataTransfer.files[0]);
				
			};

			this.ui.txt.focus();
		
		}
	
	}

	loadFile(f) {

		const rdr = new FileReader();

		rdr.onload = () => {

			this.bin = {
				nnm: f.name,
				dat: new Uint8Array(/** @type {!ArrayBuffer} */ (rdr.result)),
				siz: f.size
			};

			this.renderFile();
		
		};

		rdr.readAsArrayBuffer(f);
	
	}

	renderFile() {

		this.ui.wrp.classList.add("bin");
		const s = this.bin.siz || this.bin.dat.length;

		this.ui.nnm.innerText = this.bin.nnm;
		this.ui.siz.innerText = s > 1048576 ? (s / 1048576).toFixed(2) + "MB" : (s / 1024).toFixed(2) + "KB";
        
		this.ui.act.innerText = this.dec ? "download" : "clear";
        
		this.ui.act.onclick = this.dec ? () => {

			const u = URL.createObjectURL(new Blob(
				[this.bin.dat],
				{
					type: "application/octet-stream"
				}
			));
			const a = document.createElement("a");

			a.href = u;
			a.download = this.bin.nnm;
			a.click();
			URL.revokeObjectURL(u);
		
		} : () => {

			this.bin = null;
			this.ui.fin.value = "";
			this.ui.wrp.classList.remove("bin");
		
		};
	
	}

	info(str, elt = this.ui.btn) {

		clearTimeout(this.timed);
		const prev = elt.innerText;

		elt.innerText = str;
		this.timed = setTimeout(
			() =>
				elt.innerText = prev,
			2345
		);

	}

	async run() {
        
		try {

			if(this.dec)
				await this.decryptIt();
			else
				await this.encryptIt();
		
		}
		catch(err) {
 
			console.error(err);
			this.info("error");
		
		}
	
	}

	async encryptIt() {

		if(!this.bin && !this.ui.txt.reportValidity())
			return;

		const passwd = this.ui.pwd;

		if(!passwd.value) {

			passwd.value = Passwd.generate();
			this.ui.cwd.classList.add("show");
		
		}

		const pwd = this.ui.pwd.value;

		let dat;

		if(this.bin) {

			const hds = new TextEncoder()
			.encode(`\0F\0${this.bin.nnm}\n`);

			dat = new Uint8Array(hds.length + this.bin.dat.length);

			dat.set(
				hds,
				0
			);

			dat.set(
				this.bin.dat,
				hds.length
			);
				
		}
		else {

			dat = new TextEncoder()
			.encode(this.ui.txt.value);
				
		}

		const slt = crypto.getRandomValues(new Uint8Array(16));
		const ivc = crypto.getRandomValues(new Uint8Array(12));

		const prm = Promise.all([
			this.gzip(
				dat,
				CompressionStream
			),
			this.derive(
				pwd,
				slt
			)
		])
		.then(([z, k]) =>
			crypto.subtle.encrypt(
				{
					name: "AES-GCM",
					iv: ivc
				},
				k,
				z
			))
		.then(enc => {

			const pck = new Uint8Array(28 + enc.byteLength);

			pck.set(
				slt,
				0
			);
			pck.set(
				ivc,
				16
			);
			pck.set(
				new Uint8Array(enc),
				28
			);

			return `${location.origin}${location.pathname}#${encodeURIComponent(this.ui.ttl.value)}|${pck.toBase64(this.b64)}`;
			
		});

		try {

			const dsc = this.ui.ttl.value || "URLock";

			await navigator
			.share({
				title: dsc,
				//text: dsc,
				url: await prm
			});

			this.info("shared");

		}
		catch(err) {

			await navigator.clipboard.write([new ClipboardItem({
				[this.blb.type]: prm.then(u =>
					new Blob(
						[u],
						this.blb
					))
			})]);

			await prm;
                
			this.info("copied");
					
		}

	}

	async decryptIt() {

		if(!this.ui.pwd.reportValidity())
			return;

		const pwd = this.ui.pwd.value;

		const bytes = Uint8Array.fromBase64(
			this.dat,
			this.b64
		);
		const slt = bytes.slice(
			0,
			16
		);
		const ivc = bytes.slice(
			16,
			28
		);
		const enc = bytes.slice(28);

		const key = await this.derive(
			pwd,
			slt
		);
		const dec = await crypto.subtle.decrypt(
			{
				name: "AES-GCM",
				iv: ivc
			},
			key,
			enc
		);
		const raw = await this.gzip(
			dec,
			DecompressionStream
		);

		// Check Magic: \0F\0
		if(raw[0] === 0 && raw[1] === 70 && raw[2] === 0) {

			const nl = raw.indexOf(10);

			if(nl > -1) {

				this.bin = {
					nnm: new TextDecoder()
					.decode(raw.slice(
						3,
						nl
					)),
					dat: raw.slice(nl + 1)
				};
						
				this.renderFile();
					
			}
				
		}
		else {

			this.ui.txt.value = new TextDecoder()
			.decode(raw);
				
		}

		this.ui.wrp.classList.add("res");

		this.ui.pwd.value = "";

	}

	async derive(pwd, slt) {

		return crypto.subtle.deriveKey(
			{
				name: "PBKDF2",
				salt: slt,
				iterations: 256000,
				hash: "SHA-256"
			},
			await crypto.subtle.importKey(
				"raw",
				new TextEncoder()
				.encode(pwd),
				"PBKDF2",
				false,
				["deriveKey"]
			),
			{
				name: "AES-GCM",
				length: 256
			},
			false,
			["encrypt", "decrypt"]
		);
	
	}

	gzip(dat, ops) {

		return new Response(new Response(dat).body.pipeThrough(new ops("gzip")))
		.arrayBuffer()
		.then(res =>
			new Uint8Array(res));
	
	}

}

window.onload = () =>
	new URLock();