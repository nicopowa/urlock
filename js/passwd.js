class Passwd {

	static pick(chars, count) {

		let out = "";
		const bytes = new Uint8Array(count * 2);

		while(out.length < count) {

			crypto.getRandomValues(bytes);

			for(const b of bytes) {

				if(b < 256 - (256 % chars.length)) {

					out += chars[b % chars.length];

					if(out.length === count)
						break;

				}

			}

		}

		return out;

	}

	static generate() {

		const num = "2346789";
		const chars = [
			...Passwd.pick(
				"!@#$%&*()_+-",
				2
			),
			...Passwd.pick(
				num,
				3
			),
			...Passwd.pick(
				"ABCDEFGHJKLMNPQRTUVWXYabcdefghijkmnpqrtwxyz" + num,
				9
			)
		];

		const rand = crypto.getRandomValues(new Uint32Array(chars.length));

		for(let i = chars.length - 1; i > 0; i--) {

			const j = Number(rand[i]) % (i + 1);

			[chars[i], chars[j]] = [chars[j], chars[i]];

		}

		return chars.join("");

	}

}
