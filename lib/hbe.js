(() => {
	const cryptoObj = window.crypto;
	const storage = window.localStorage;

	const storageName = `hexo-blog-encrypt:#${window.location.pathname}`;

	// As we can't detect the wrong password with AES-CBC,
	// so adding an empty div and check it when decrption.
	const knownPrefix = "<hbe-prefix></hbe-prefix>";

	const mainElement = document.getElementById("hexo-blog-encrypt");
	const wrongPassMessage = mainElement.dataset.wpm;
	const wrongHashMessage = mainElement.dataset.whm;
	const dataElement = mainElement.getElementsByTagName("script").hbeData;
	const encryptedData = dataElement.innerText;
	const HmacDigest = dataElement.dataset.hmacdigest;
	// If the plugin version is updated but the blog is not regenerated (e.g. caching), the legacy fixed salt value is used.
	const encoder = new TextEncoder();
	const decoder = new TextDecoder();

	const keySalt = dataElement.dataset.keysalt
		? hexToArray(dataElement.dataset.keysalt)
		: encoder.encode("hexo-blog-encrypt的作者们都是大帅比!");

	const ivSalt = dataElement.dataset.ivsalt
		? hexToArray(dataElement.dataset.ivsalt)
		: encoder.encode("hexo-blog-encrypt是地表最强Hexo加密插件!");

	function hexToArray(s) {
		return new Uint8Array(
			s.match(/[\da-f]{2}/gi).map((h) => {
				return parseInt(h, 16);
			}),
		);
	}

	function arrayBufferToHex(arrayBuffer) {
		if (
			typeof arrayBuffer !== "object" ||
			arrayBuffer === null ||
			typeof arrayBuffer.byteLength !== "number"
		) {
			throw new TypeError("Expected input to be an ArrayBuffer");
		}

		var view = new Uint8Array(arrayBuffer);
		var result = "";
		var value;

		for (var i = 0; i < view.length; i++) {
			value = view[i].toString(16);
			result += value.length === 1 ? `0${value}` : value;
		}

		return result;
	}

	async function getExecutableScript(oldElem) {
		const out = document.createElement("script");
		const attList = [
			"type",
			"text",
			"src",
			"crossorigin",
			"defer",
			"referrerpolicy",
		];
		attList.forEach((att) => {
			if (oldElem[att]) out[att] = oldElem[att];
		});

		return out;
	}

	async function convertHTMLToElement(content) {
		const out = document.createElement("div");
		out.innerHTML = content;
		out.querySelectorAll("script").forEach(async (elem) => {
			elem.replaceWith(await getExecutableScript(elem));
		});

		return out;
	}

	function getKeyMaterial(password) {
		const encoder = new TextEncoder();
		return cryptoObj.subtle.importKey(
			"raw",
			encoder.encode(password),
			{
				name: "PBKDF2",
			},
			false,
			["deriveKey", "deriveBits"],
		);
	}

	function getHmacKey(keyMaterial) {
		return cryptoObj.subtle.deriveKey(
			{
				name: "PBKDF2",
				hash: "SHA-256",
				salt: keySalt.buffer,
				iterations: 1024,
			},
			keyMaterial,
			{
				name: "HMAC",
				hash: "SHA-256",
				length: 256,
			},
			true,
			["verify"],
		);
	}

	function getDecryptKey(keyMaterial) {
		return cryptoObj.subtle.deriveKey(
			{
				name: "PBKDF2",
				hash: "SHA-256",
				salt: keySalt.buffer,
				iterations: 1024,
			},
			keyMaterial,
			{
				name: "AES-CBC",
				length: 256,
			},
			true,
			["decrypt"],
		);
	}

	function getIv(keyMaterial) {
		return cryptoObj.subtle.deriveBits(
			{
				name: "PBKDF2",
				hash: "SHA-256",
				salt: ivSalt.buffer,
				iterations: 512,
			},
			keyMaterial,
			16 * 8,
		);
	}

	async function verifyContent(key, content) {
		const encoder = new TextEncoder();
		const encoded = encoder.encode(content);

		const signature = hexToArray(HmacDigest);

		const result = await cryptoObj.subtle.verify(
			{
				name: "HMAC",
				hash: "SHA-256",
			},
			key,
			signature,
			encoded,
		);
		console.log(`Verification result: ${result}`);
		if (!result) {
			alert(wrongHashMessage);
			console.log(`${wrongHashMessage}, got `, signature, ` but proved wrong.`);
		}
		return result;
	}

	async function decrypt(decryptKey, iv, hmacKey) {
		const typedArray = hexToArray(encryptedData);

		const result = await cryptoObj.subtle
			.decrypt(
				{
					name: "AES-CBC",
					iv: iv,
				},
				decryptKey,
				typedArray.buffer,
			)
			.then(async (result) => {
				const decoded = decoder.decode(result);

				// check the prefix, if not then we can sure here is wrong password.
				if (!decoded.startsWith(knownPrefix)) {
					throw "Decode successfully but not start with KnownPrefix.";
				}

				const hideButton = document.createElement("button");
				hideButton.textContent = "Encrypt again";
				hideButton.type = "button";
				hideButton.classList.add("hbe-button");
				hideButton.addEventListener("click", () => {
					window.localStorage.removeItem(storageName);
					window.location.reload();
				});

				document.getElementById("hexo-blog-encrypt").style.display = "inline";
				document.getElementById("hexo-blog-encrypt").innerHTML = "";
				document
					.getElementById("hexo-blog-encrypt")
					.appendChild(await convertHTMLToElement(decoded));
				document.getElementById("hexo-blog-encrypt").appendChild(hideButton);

				// support html5 lazyload functionality.
				document.querySelectorAll("img").forEach((elem) => {
					if (elem.getAttribute("data-src") && !elem.src) {
						elem.src = elem.getAttribute("data-src");
					}
				});

				// support theme-next refresh
				window.NexT &&
					NexT.boot &&
					typeof NexT.boot.refresh === "function" &&
					NexT.boot.refresh();

				// TOC part
				var tocDiv = document.getElementById("toc-div");
				if (tocDiv) {
					tocDiv.style.display = "inline";
				}

				var tocDivs = document.getElementsByClassName("toc-div-class");
				if (tocDivs && tocDivs.length > 0) {
					for (var idx = 0; idx < tocDivs.length; idx++) {
						tocDivs[idx].style.display = "inline";
					}
				}

				// trigger event
				var event = new Event("hexo-blog-decrypt");
				window.dispatchEvent(event);

				return await verifyContent(hmacKey, decoded);
			})
			.catch((e) => {
				alert(wrongPassMessage);
				console.log(e);
				return false;
			});

		return result;
	}

	async function hbeLoader() {
		const passInput = document.getElementById("hbePass");
		if (!passInput) return; // 保护性检查

		// 尝试从缓存自动解密
		const oldStorageData = JSON.parse(storage.getItem(storageName));
		if (oldStorageData) {
			console.log(`Auto-decrypting with keys from localStorage...`);
			try {
				const iv = hexToArray(oldStorageData.iv); // 这里 oldStorageData.iv 已经是 hex 字符串

				// 导入 JWK key
				const [decryptKey, hmacKey] = await Promise.all([
					cryptoObj.subtle.importKey(
						"jwk",
						oldStorageData.dk,
						{ name: "AES-CBC", length: 256 },
						true,
						["decrypt"],
					),
					cryptoObj.subtle.importKey(
						"jwk",
						oldStorageData.hmk,
						{ name: "HMAC", hash: "SHA-256", length: 256 },
						true,
						["verify"],
					),
				]);

				const result = await decrypt(decryptKey, iv, hmacKey);
				if (!result) {
					storage.removeItem(storageName); // 解密失败清除无效缓存
				}
			} catch (e) {
				console.error("Auto-decryption error:", e);
				storage.removeItem(storageName);
			}
		}

		// 绑定交互事件
		passInput.addEventListener("keydown", async (event) => {
			if (event.key === "Enter") {
				const password = passInput.value;
				if (!password) return;

				try {
					const keyMaterial = await getKeyMaterial(password);

					// 并行生成 key，稍微提升速度
					const [hmacKey, decryptKey, ivBuffer] = await Promise.all([
						getHmacKey(keyMaterial),
						getDecryptKey(keyMaterial),
						getIv(keyMaterial),
					]);

					const iv = new Uint8Array(ivBuffer); // deriveBits 返回的是 ArrayBuffer

					const success = await decrypt(decryptKey, iv, hmacKey);

					if (success) {
						// 导出 Key 并存储
						const [dkExport, hmkExport] = await Promise.all([
							cryptoObj.subtle.exportKey("jwk", decryptKey),
							cryptoObj.subtle.exportKey("jwk", hmacKey),
						]);

						storage.setItem(
							storageName,
							JSON.stringify({
								dk: dkExport,
								iv: arrayBufferToHex(iv), // 存储 hex 字符串
								hmk: hmkExport,
							}),
						);
					}
				} catch (e) {
					console.error("Password decryption flow failed:", e);
					alert(wrongPassMessage);
				}
			}
		});
	}

	hbeLoader();
})();
