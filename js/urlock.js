class URLock {

	constructor() {

		const $ = id =>
			document.getElementById(id);

		this.ui = {
			wrp: $("wrp"),
			tit: $("tit"),
			row: $("row"),
			pwd: $("pwd"),
			cwd: $("cwd"),
			rev: $("rev"),
			btn: $("btn"),
			ttl: $("ttl"),
			txt: $("txt"),
			nnm: $("nnm"),
			siz: $("siz"),
			act: $("act"),
			fin: $("fin")
		};

		this.b64 = {
			alphabet: "base64url"
		};

		this.timed = 0;
		this.dat = "";
		this.bin = [];
		this.its = +(new URLSearchParams(document.location.search)
		.get("its")) || 600000;

		const hsh = location.hash.slice(1);

		this.dec = !!hsh;

		this.ui.wrp.className = this.dec ? "dec" : "enc";
		this.ui.btn.innerText = this.dec ? "unlock" : "share";
		this.ui.btn.onclick = () =>
			this.run();

		this.ui.pwd.addEventListener(
			"keydown",
			e => {

				if(e.key === "Enter")
					this.run();
			
			}
		);

		this.ui.rev.onclick = () =>
			[this.ui.rev, this.ui.pwd].forEach(el =>
				el.classList.toggle("show"));

		this.ui.cwd.onclick = () =>
			navigator.clipboard.writeText(this.ui.pwd.value);

		if(this.dec) {

			const spl = hsh.split(/\||%7C/);

			if(spl.length > 1)
				this.ui.tit.innerText = decodeURIComponent(spl.shift());

			this.dat = spl[0];
			this.ui.pwd.focus();
			this.ui.pwd.onpaste = () =>
				setTimeout(
					() =>
						this.run(),
					1
				);
		
		}
		else {

			this.ui.fin.multiple = true;

			this.ui.fin.onchange = e =>
				this.loadFiles(e.target.files);

			document.body.ondragover = e =>
				e.preventDefault();

			document.body.ondrop = e => {

				e.preventDefault();
				this.loadFiles(e.dataTransfer.files);
			
			};

			this.ui.txt.focus();
		
		}
	
	}

	async loadFiles(fls = []) {

		this.bin.push(...await Promise.all([...fls].map(async f =>
			({
				nnm: f.name,
				dat: new Uint8Array(await f.arrayBuffer())
			}))));

		this.renderFile();

	}

	async save(f) {

		await new Promise(wait =>
			setTimeout(
				wait,
				123
			));

		const a = document.createElement("a");

		a.href = URL.createObjectURL(new Blob(
			[f.dat],
			{
				type: "application/octet-stream"
			}
		));
		a.download = f.nnm;
		a.click();
		//setTimeout(() =>
		URL.revokeObjectURL(a.href);
		//1000);

	}

	renderFile() {

		const bins = this.bin.length;

		this.ui.wrp.classList.toggle(
			"bin",
			bins > 0
		);

		if(!bins) {

			this.ui.nnm.replaceChildren();
			this.ui.siz.innerText = "";

			return;

		}

		const s = this.bin.reduce(
			(acc, f) =>
				acc + f.dat.length,
			0
		);

		this.ui.nnm.replaceChildren(...this.bin.map(f =>
			Object.assign(
				document.createElement("div"),
				{
					innerText: f.nnm,
					onclick: this.dec ? () =>
						this.save(f) : null
				}
			)));

		this.ui.siz.innerText = `${bins} file${bins !== 1 ? "s" : ""} ${(s / 1024).toFixed(2)}KB`;

		this.ui.act.onclick = this.dec ? async () => {

			for(const f of this.bin)
				await this.save(f);
		
		} : () => {

			this.bin = [];
			this.ui.fin.value = "";
			this.renderFile();

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

		if(!this.bin.length && !this.ui.txt.reportValidity())
			return;

		const passwd = this.ui.pwd;

		if(!passwd.value)
			passwd.value = Passwd.generate();

		const pwd = this.ui.pwd.value;
		const txt = URLock.enc.encode(this.ui.txt.value);

		const dat = this.bin.length
			? new Blob([
				URLock.enc.encode(`\0M\0${JSON.stringify([txt.length, ...this.bin.map(f =>
					[f.nnm, f.dat.length])])}\n`),
				txt,
				...this.bin.map(f =>
					f.dat)
			])
			: txt;

		const slt = crypto.getRandomValues(new Uint8Array(16));
		const ivc = crypto.getRandomValues(new Uint8Array(12));

		const [z, k] = await Promise.all([
			this.gzipIt(
				dat,
				CompressionStream
			),
			this.deriveIt(
				pwd,
				slt
			)
		]);

		const enc = await crypto.subtle.encrypt(
			{
				name: "AES-GCM",
				iv: ivc
			},
			k,
			z
		);

		const pck = new Uint8Array(28 + enc.byteLength);

		pck.set(slt);
		pck.set(
			ivc,
			16
		);
		pck.set(
			new Uint8Array(enc),
			28
		);

		const url = `${location.origin}${location.pathname}#${encodeURIComponent(this.ui.ttl.value)}|${pck.toBase64(this.b64)}`;

		try {

			await navigator.share({
				title: this.ui.ttl.value || "URLock",
				url
			});

			this.info("shared");

		}
		catch{

			await navigator.clipboard.writeText(url);
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

		const slt = bytes.subarray(
			0,
			16
		);

		const ivc = bytes.subarray(
			16,
			28
		);

		const enc = bytes.subarray(28);

		const key = await this.deriveIt(
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

		const raw = await this.gzipIt(
			dec,
			DecompressionStream
		);

		const nl = raw.indexOf(10);

		if(!raw[0] && !raw[2] && nl > 2 && (raw[1] === 70 || raw[1] === 77)) {

			const hdr = URLock.dec.decode(raw.subarray(
				3,
				nl
			));

			// legacy single file
			if(raw[1] === 70) {

				this.bin = [{
					nnm: hdr,
					dat: raw.subarray(nl + 1)
				}];

			}
			else {

				const prs = JSON.parse(hdr);
				let [off, ...fls] = Array.isArray(prs) ? prs : [];

				this.ui.txt.value = URLock.dec.decode(raw.subarray(
					nl + 1,
					nl + 1 + off
				));

				off += nl + 1;

				this.bin = fls.map(([nnm, siz]) =>
					({
						nnm,
						dat: raw.subarray(
							off,
							off += siz
						)
					}));

			}

			this.renderFile();

		}
		else {

			this.ui.txt.value = URLock.dec.decode(raw);

		}

		this.ui.wrp.classList.add("res");
		this.ui.pwd.value = "";

	}

	async deriveIt(pwd, slt) {

		return crypto.subtle.deriveKey(
			{
				name: "PBKDF2",
				salt: slt,
				iterations: this.its,
				hash: "SHA-256"
			},
			await crypto.subtle.importKey(
				"raw",
				URLock.enc.encode(pwd),
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

	async gzipIt(dat, ops) {

		const res = await new Response(new Response(dat).body.pipeThrough(new ops("gzip")))
		.arrayBuffer();

		return new Uint8Array(res);

	}

	static enc = new TextEncoder();

	static dec = new TextDecoder();

}

window.onload = () =>
	new URLock();
