class URLock {

	constructor() {

		this.ui = Object.entries({
			wrp: "wrp",
			row: "row",
			pwd: "pwd",
			btn: "btn",
			txt: "txt",
			nfo: "nfo",
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
        
		this.bin = null;
		this.dec = !!location.hash.replace(
			/^#/,
			""
		);
        
		this.ui.wrp.className = this.dec ? "dec" : "enc";
		this.ui.btn.innerText = this.dec ? "decrypt" : "encrypt";

		this.ui.btn.addEventListener(
			"click",
			() =>
				this.run()
		);
		this.ui.pwd.addEventListener(
			"keydown",
			e =>
				e.key === "Enter" && this.run()
		);

		if(!this.dec) {

			this.ui.fin.addEventListener(
				"change",
				e =>
					e.target.files[0] && this.loadFile(e.target.files[0])
			);
            
			document.body.addEventListener(
				"dragover",
				e => {
 
					e.preventDefault();
					e.dataTransfer.dropEffect = "copy";
				
				}
			);
            
			document.body.addEventListener(
				"drop",
				e => {
 
					e.preventDefault();
 
					if(e.dataTransfer.files[0])
						this.loadFile(e.dataTransfer.files[0]);
				
				}
			);

			this.ui.txt.focus();
		
		}
		else {

			this.ui.pwd.focus();
		
		}
	
	}

	loadFile(f) {

		const rdr = new FileReader();

		rdr.onload = e => {

			this.bin = {
				nnm: f.name,
				dat: new Uint8Array(e.target.result),
				siz: f.size
			};

			this.renderFile();
		
		};

		rdr.readAsArrayBuffer(f);
	
	}

	renderFile() {

		this.ui.wrp.classList.add("bin");
		const s = this.bin.siz || this.bin.dat.length;

		this.ui.nfo.innerText = `${this.bin.nnm}\n${s > 1048576 ? (s / 1048576).toFixed(2) + "MB" : (s / 1024).toFixed(2) + "KB"}`;
        
		this.ui.act.innerText = this.dec ? "save" : "clear";
        
		this.ui.act.onclick = this.dec ? () => {

			const u = URL.createObjectURL(new Blob([this.bin.dat]));
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

	info(str) {

		clearTimeout(this.timed);
		const prev = this.ui.btn.innerText;

		this.ui.btn.innerText = str;
		this.timed = setTimeout(
			() =>
				this.ui.btn.innerText = prev,
			2345
		);

	}

	async run() {

		if(!this.dec && !this.bin && !this.ui.txt.reportValidity())
			return;

		if(!this.ui.pwd.reportValidity())
			return;

		const pwd = this.ui.pwd.value;
		const hsh = location.hash.replace(
			/^#/,
			""
		);
        
		try {

			if(this.dec) {

				// Decrypt
				const bytes = Uint8Array.fromBase64(
					hsh,
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

				location.hash = "";
				this.ui.pwd.value = "";

			}
			else {

				// Encrypt
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

					return `${location.origin}${location.pathname}#${pck.toBase64(this.b64)}`;
			
				});
				
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
		catch(err) {
 
			console.error(err);
			this.info("error");
		
		}
	
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

	async gzip(dat, ops) {

		return new Uint8Array(await new Response(new Response(dat).body.pipeThrough(new ops("gzip")))
		.arrayBuffer());
	
	}

}
window.onload = () =>
	new URLock();