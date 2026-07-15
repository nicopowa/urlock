class Passwd {

	static LENGTH = 13;

	static NUMBERS = "2346789";

	static LETTERS = "ABCDEFGHJKLMNPQRTUVWXYabcdefghijkmnpqrtwxyz";

	static ALPHANUM = Passwd.LETTERS + Passwd.NUMBERS;

	static SPECIALS = "!@#$%&*()_+-";

	static FORCE_NUMBERS = 2;

	static FORCE_SPECIAL = 1;

	static rand(len) {

		return crypto.getRandomValues(new Uint32Array(len));
	
	}

	static pick(alphabet, count) {

		let out = "";
		const mask = (2 << Math.floor(Math.log2(alphabet.length - 1))) - 1;
		const step = Math.ceil(1.6 * mask * count / alphabet.length);

		while(out.length < count) {

			const bytes = Passwd.rand(step);

			for(let i = 0; i < step && out.length < count; i++) {

				const ch = alphabet[bytes[i] & mask];

				if(ch)
					out += ch;
			
			}
		
		}

		return out;
	
	}

	static shuffle(arr) {

		const r = Passwd.rand(arr.length);

		for(let i = arr.length - 1; i > 0; i--) {

			const j = Math.floor(r[i] / 4294967296 * (i + 1));

			[arr[i], arr[j]] = [arr[j], arr[i]];
		
		}

		return arr;
	
	}

	static generate() {

		return Passwd.shuffle([
			...Passwd.pick(
				Passwd.SPECIALS,
				Passwd.FORCE_SPECIAL
			),
			...Passwd.pick(
				Passwd.NUMBERS,
				Passwd.FORCE_NUMBERS
			),
			...Passwd.pick(
				Passwd.ALPHANUM,
				Passwd.LENGTH - Passwd.FORCE_NUMBERS - Passwd.FORCE_SPECIAL
			)
		])
		.join("");
	
	}

}