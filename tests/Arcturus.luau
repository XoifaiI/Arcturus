--!strict
--!optimize 2
--!native

local Testing = require("@self/Testing")
local Arcturus = require("@self/Arcturus")

local Describe = Testing.Describe
local Test = Testing.Test
local Expect = Testing.Expect

local function RandomBytes(Length: number): buffer
	local Bytes = buffer.create(Length)
	for Index = 0, Length - 1 do
		buffer.writeu8(Bytes, Index, math.random(0, 255))
	end
	return Bytes
end

local function ZeroBytes(Length: number): buffer
	return buffer.create(Length)
end

local function BytesEqual(A: buffer, B: buffer): boolean
	if buffer.len(A) ~= buffer.len(B) then
		return false
	end
	for Index = 0, buffer.len(A) - 1 do
		if buffer.readu8(A, Index) ~= buffer.readu8(B, Index) then
			return false
		end
	end
	return true
end

local function CopyBuffer(Source: buffer): buffer
	local Length = buffer.len(Source)
	local Copy = buffer.create(Length)
	buffer.copy(Copy, 0, Source, 0, Length)
	return Copy
end

local function FlipBit(Source: buffer, ByteIndex: number, BitIndex: number): buffer
	local Copy = CopyBuffer(Source)
	local Byte = buffer.readu8(Copy, ByteIndex)
	local Flipped = bit32.bxor(Byte, bit32.lshift(1, BitIndex))
	buffer.writeu8(Copy, ByteIndex, Flipped)
	return Copy
end

local function BufferToHex(Buf: buffer): string
	local Hex = {}
	for Index = 0, buffer.len(Buf) - 1 do
		table.insert(Hex, string.format("%02x", buffer.readu8(Buf, Index)))
	end
	return table.concat(Hex)
end

local function HexToBuffer(Hex: string): buffer
	local Length = #Hex / 2
	local Buf = buffer.create(Length)
	for Index = 0, Length - 1 do
		local Byte = tonumber(string.sub(Hex, Index * 2 + 1, Index * 2 + 2), 16)
		buffer.writeu8(Buf, Index, Byte :: number)
	end
	return Buf
end

Testing.Entry(function()
	Describe("Constants", function()
		Test("KEY_SIZE is 32", function()
			Expect(Arcturus.KEY_SIZE).ToBe(32)
		end)

		Test("NONCE_SIZE is 32", function()
			Expect(Arcturus.NONCE_SIZE).ToBe(32)
		end)

		Test("COMMITMENT_SIZE is 32", function()
			Expect(Arcturus.COMMITMENT_SIZE).ToBe(32)
		end)

		Test("TAG_SIZE is 16", function()
			Expect(Arcturus.TAG_SIZE).ToBe(16)
		end)

		Test("OVERHEAD is 48", function()
			Expect(Arcturus.OVERHEAD).ToBe(48)
		end)
	end)

	Describe("Official Test Vectors", function()
		Test("Vector 1: Empty message, zero key/nonce", function()
			local Key = HexToBuffer("0000000000000000000000000000000000000000000000000000000000000000")
			local Nonce = HexToBuffer("0000000000000000000000000000000000000000000000000000000000000000")
			local Message = buffer.create(0)

			local Ciphertext, Commitment, Tag = Arcturus.Encrypt(Message, Key, Nonce)

			Expect(buffer.len(Ciphertext)).ToBe(0)
			Expect(BufferToHex(Commitment)).ToBe("2ebc70f01c7538605d08ed84a508dc41b3a0b05687687bf9455d6733c92c8d15")
			Expect(BufferToHex(Tag)).ToBe("5a92801d1ed450b50ebf15e893c4550b")

			local Plaintext = Arcturus.Decrypt(Ciphertext, Key, Nonce, Commitment, Tag)
			Expect(Plaintext).Never.ToBeNil()
			Expect(buffer.len(Plaintext :: buffer)).ToBe(0)
		end)

		Test("Vector 2: 64-byte zero message, zero key/nonce", function()
			local Key = HexToBuffer("0000000000000000000000000000000000000000000000000000000000000000")
			local Nonce = HexToBuffer("0000000000000000000000000000000000000000000000000000000000000000")
			local Message = HexToBuffer("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")

			local Ciphertext, Commitment, Tag = Arcturus.Encrypt(Message, Key, Nonce)

			Expect(BufferToHex(Ciphertext)).ToBe("67e3dc0cd6eef8ad75d15350f0a6056f0bd553c7b111dcbc8df0f060ace138bea786903dd758ccb04135c5d675d3f2d06c544c39e2a9313c54e4aeccde3d3e47")
			Expect(BufferToHex(Commitment)).ToBe("2ebc70f01c7538605d08ed84a508dc41b3a0b05687687bf9455d6733c92c8d15")
			Expect(BufferToHex(Tag)).ToBe("43298a645064bffcb4b75a7d81e19dcd")

			local Plaintext = Arcturus.Decrypt(Ciphertext, Key, Nonce, Commitment, Tag)
			Expect(Plaintext).Never.ToBeNil()
			Expect(BytesEqual(Plaintext :: buffer, Message)).ToBe(true)
		end)

		Test("Vector 3: 'Arcturus' with sequential key/nonce", function()
			local Key = HexToBuffer("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
			local Nonce = HexToBuffer("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
			local Message = buffer.fromstring("Arcturus")

			local Ciphertext, Commitment, Tag = Arcturus.Encrypt(Message, Key, Nonce)

			Expect(BufferToHex(Ciphertext)).ToBe("1d747bbe7d831fa4")
			Expect(BufferToHex(Commitment)).ToBe("582ef54226ad5dee3db079da8e748989ca81fab8f01de0b1b007492b9818166e")
			Expect(BufferToHex(Tag)).ToBe("8bfbcf2d06fd33ad5ca9333719f4ece3")

			local Plaintext = Arcturus.Decrypt(Ciphertext, Key, Nonce, Commitment, Tag)
			Expect(Plaintext).Never.ToBeNil()
			Expect(buffer.tostring(Plaintext :: buffer)).ToBe("Arcturus")
		end)

		Test("Vector 4: 'The quick brown fox...' with ASCII key/nonce", function()
			local Key = HexToBuffer("41726374757275735f546573744b65795f303030303030303030303030303030")
			local Nonce = HexToBuffer("41726374757275735f4e6f6e63655f5f30303030303030303030303030303030")
			local Message = buffer.fromstring("The quick brown fox jumps over the lazy dog")

			local Ciphertext, Commitment, Tag = Arcturus.Encrypt(Message, Key, Nonce)

			Expect(BufferToHex(Ciphertext)).ToBe("9ef0fa2d9d50a7cf274fe9fd507531e559a5951043a2fdbdb4d3616a5ece48b6ec6b8d113f329a7669613b")
			Expect(BufferToHex(Commitment)).ToBe("2681b8bab8946a3f719b3d52fff47b2485d5302350333e51cc97fb501ac5cd10")
			Expect(BufferToHex(Tag)).ToBe("f78a6b12d65cd8c6681ac0e37e78728f")

			local Plaintext = Arcturus.Decrypt(Ciphertext, Key, Nonce, Commitment, Tag)
			Expect(Plaintext).Never.ToBeNil()
			Expect(buffer.tostring(Plaintext :: buffer)).ToBe("The quick brown fox jumps over the lazy dog")
		end)

		Test("Vector 5: 'Attack at dawn' with AAD 'v1.0'", function()
			local Key = HexToBuffer("5365637265744b65795f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f")
			local Nonce = HexToBuffer("556e697175654e6f6e63655f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f")
			local Message = buffer.fromstring("Attack at dawn")
			local AAD = buffer.fromstring("v1.0")

			local Ciphertext, Commitment, Tag = Arcturus.Encrypt(Message, Key, Nonce, AAD)

			Expect(BufferToHex(Ciphertext)).ToBe("b6d0dd0d2daa90dc1210ae653129")
			Expect(BufferToHex(Commitment)).ToBe("b23e4dd21edaefcb993c97fd45f62105a32c565be7008885da3cda4e91a6a101")
			Expect(BufferToHex(Tag)).ToBe("029ad8c8a2e67631efd7135f46f8daea")

			local Plaintext = Arcturus.Decrypt(Ciphertext, Key, Nonce, Commitment, Tag, AAD)
			Expect(Plaintext).Never.ToBeNil()
			Expect(buffer.tostring(Plaintext :: buffer)).ToBe("Attack at dawn")
		end)

		Test("Vector 6: 63-byte sequential message (block boundary -1)", function()
			local Key = HexToBuffer("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
			local Nonce = HexToBuffer("5555555555555555555555555555555555555555555555555555555555555555")
			local Message = HexToBuffer("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e")

			local Ciphertext, Commitment, Tag = Arcturus.Encrypt(Message, Key, Nonce)

			Expect(BufferToHex(Ciphertext)).ToBe("1944d457032debc2171de45ce3776b71b63c49d37b7bfeaba884afede899c1e98831e991d9e013ae67fa7ca6686d0b421f23bfc537713d614792916c64a1ea")
			Expect(BufferToHex(Commitment)).ToBe("2c36f67ac5138071625aa6dd5e77db4e250214b0f832b30097c45aeb0b7d0d7a")
			Expect(BufferToHex(Tag)).ToBe("d89894ba76c689a486dab3394102f86b")

			local Plaintext = Arcturus.Decrypt(Ciphertext, Key, Nonce, Commitment, Tag)
			Expect(Plaintext).Never.ToBeNil()
			Expect(BytesEqual(Plaintext :: buffer, Message)).ToBe(true)
		end)

		Test("Vector 7: 65-byte sequential message (block boundary +1)", function()
			local Key = HexToBuffer("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
			local Nonce = HexToBuffer("4444444444444444444444444444444444444444444444444444444444444444")
			local Message = HexToBuffer("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40")

			local Ciphertext, Commitment, Tag = Arcturus.Encrypt(Message, Key, Nonce)

			Expect(BufferToHex(Ciphertext)).ToBe("262770bb758d4ed567ac4d1c7c225e216519347096b0355e55ee7450e4966122a347e1d2ce26fb69c0b25af0ae18d31d940ad5bc88b5daa3f1a59c35de10e35023")
			Expect(BufferToHex(Commitment)).ToBe("d34bcfff9fdf052a1b77d92785f64bcf5457dcfb1a1b3a5aadd2d40003e10ffc")
			Expect(BufferToHex(Tag)).ToBe("801dd54550c95fc1ca11c96fae7dff12")

			local Plaintext = Arcturus.Decrypt(Ciphertext, Key, Nonce, Commitment, Tag)
			Expect(Plaintext).Never.ToBeNil()
			Expect(BytesEqual(Plaintext :: buffer, Message)).ToBe(true)
		end)

		Test("Vector 8: All 0xFF key/nonce/message", function()
			local Key = HexToBuffer("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
			local Nonce = HexToBuffer("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
			local Message = HexToBuffer("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")

			local Ciphertext, Commitment, Tag = Arcturus.Encrypt(Message, Key, Nonce)

			Expect(BufferToHex(Ciphertext)).ToBe("e9fad81056edf009f38f4c813b324c32852d66a1b0983729961ef91eae479189")
			Expect(BufferToHex(Commitment)).ToBe("f3699aee51501480e1be6b8fb8bcc67e7a25166523c815c6cbf15e973a139e9f")
			Expect(BufferToHex(Tag)).ToBe("b3b8035f4b27a48d40e642b8a5a92c57")

			local Plaintext = Arcturus.Decrypt(Ciphertext, Key, Nonce, Commitment, Tag)
			Expect(Plaintext).Never.ToBeNil()
			Expect(BytesEqual(Plaintext :: buffer, Message)).ToBe(true)
		end)

		Test("Vector 9: Single byte 'X'", function()
			local Key = HexToBuffer("4200000000000000000000000000000000000000000000000000000000000000")
			local Nonce = HexToBuffer("2400000000000000000000000000000000000000000000000000000000000000")
			local Message = buffer.fromstring("X")

			local Ciphertext, Commitment, Tag = Arcturus.Encrypt(Message, Key, Nonce)

			Expect(BufferToHex(Ciphertext)).ToBe("bb")
			Expect(BufferToHex(Commitment)).ToBe("99ed516459754aa1fb527ac577052262208f7055d024f73ca4d61112340e6037")
			Expect(BufferToHex(Tag)).ToBe("88eb63279aa732a3428da35848be7638")

			local Plaintext = Arcturus.Decrypt(Ciphertext, Key, Nonce, Commitment, Tag)
			Expect(Plaintext).Never.ToBeNil()
			Expect(buffer.tostring(Plaintext :: buffer)).ToBe("X")
		end)

		Test("Vector 10: Small message with large AAD (256 bytes)", function()
			local Key = HexToBuffer("4c617267654141445f546573744b65795f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f")
			local Nonce = HexToBuffer("4c617267654141445f4e6f6e63655f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f")
			local Message = buffer.fromstring("Small message")
			local AAD = HexToBuffer("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")

			local Ciphertext, Commitment, Tag = Arcturus.Encrypt(Message, Key, Nonce, AAD)

			Expect(BufferToHex(Ciphertext)).ToBe("415e2b6580318dd226e73c6627")
			Expect(BufferToHex(Commitment)).ToBe("371c1924f42a635e3f447a7a00061b1b124c7eb7cff5119e9e09b7810e059334")
			Expect(BufferToHex(Tag)).ToBe("733970799047151bf03f6e32173e6367")

			local Plaintext = Arcturus.Decrypt(Ciphertext, Key, Nonce, Commitment, Tag, AAD)
			Expect(Plaintext).Never.ToBeNil()
			Expect(buffer.tostring(Plaintext :: buffer)).ToBe("Small message")
		end)
	end)

	Describe("Basic Encryption/Decryption", function()
		Test("Encrypts and decrypts empty message", function()
			local Key = RandomBytes(32)
			local Nonce = RandomBytes(32)
			local Message = buffer.create(0)

			local Ciphertext, Commitment, Tag = Arcturus.Encrypt(Message, Key, Nonce)
			local Plaintext = Arcturus.Decrypt(Ciphertext, Key, Nonce, Commitment, Tag)

			Expect(Plaintext).Never.ToBeNil()
			Expect(buffer.len(Plaintext :: buffer)).ToBe(0)
		end)

		Test("Encrypts and decrypts single byte", function()
			local Key = RandomBytes(32)
			local Nonce = RandomBytes(32)
			local Message = buffer.fromstring("X")

			local Ciphertext, Commitment, Tag = Arcturus.Encrypt(Message, Key, Nonce)
			local Plaintext = Arcturus.Decrypt(Ciphertext, Key, Nonce, Commitment, Tag)

			Expect(Plaintext).Never.ToBeNil()
			Expect(buffer.tostring(Plaintext :: buffer)).ToBe("X")
		end)

		Test("Encrypts and decrypts short message", function()
			local Key = RandomBytes(32)
			local Nonce = RandomBytes(32)
			local Message = buffer.fromstring("Hello, World!")

			local Ciphertext, Commitment, Tag = Arcturus.Encrypt(Message, Key, Nonce)
			local Plaintext = Arcturus.Decrypt(Ciphertext, Key, Nonce, Commitment, Tag)

			Expect(Plaintext).Never.ToBeNil()
			Expect(buffer.tostring(Plaintext :: buffer)).ToBe("Hello, World!")
		end)

		Test("Encrypts and decrypts exactly 64 bytes (one block)", function()
			local Key = RandomBytes(32)
			local Nonce = RandomBytes(32)
			local Message = RandomBytes(64)

			local Ciphertext, Commitment, Tag = Arcturus.Encrypt(Message, Key, Nonce)
			local Plaintext = Arcturus.Decrypt(Ciphertext, Key, Nonce, Commitment, Tag)

			Expect(Plaintext).Never.ToBeNil()
			Expect(BytesEqual(Plaintext :: buffer, Message)).ToBe(true)
		end)

		Test("Encrypts and decrypts 65 bytes (block + 1)", function()
			local Key = RandomBytes(32)
			local Nonce = RandomBytes(32)
			local Message = RandomBytes(65)

			local Ciphertext, Commitment, Tag = Arcturus.Encrypt(Message, Key, Nonce)
			local Plaintext = Arcturus.Decrypt(Ciphertext, Key, Nonce, Commitment, Tag)

			Expect(Plaintext).Never.ToBeNil()
			Expect(BytesEqual(Plaintext :: buffer, Message)).ToBe(true)
		end)

		Test("Encrypts and decrypts 128 bytes (two blocks)", function()
			local Key = RandomBytes(32)
			local Nonce = RandomBytes(32)
			local Message = RandomBytes(128)

			local Ciphertext, Commitment, Tag = Arcturus.Encrypt(Message, Key, Nonce)
			local Plaintext = Arcturus.Decrypt(Ciphertext, Key, Nonce, Commitment, Tag)

			Expect(Plaintext).Never.ToBeNil()
			Expect(BytesEqual(Plaintext :: buffer, Message)).ToBe(true)
		end)

		Test("Encrypts and decrypts 1000 bytes", function()
			local Key = RandomBytes(32)
			local Nonce = RandomBytes(32)
			local Message = RandomBytes(1000)

			local Ciphertext, Commitment, Tag = Arcturus.Encrypt(Message, Key, Nonce)
			local Plaintext = Arcturus.Decrypt(Ciphertext, Key, Nonce, Commitment, Tag)

			Expect(Plaintext).Never.ToBeNil()
			Expect(BytesEqual(Plaintext :: buffer, Message)).ToBe(true)
		end)

		Test("Encrypts and decrypts 10000 bytes", function()
			local Key = RandomBytes(32)
			local Nonce = RandomBytes(32)
			local Message = RandomBytes(10000)

			local Ciphertext, Commitment, Tag = Arcturus.Encrypt(Message, Key, Nonce)
			local Plaintext = Arcturus.Decrypt(Ciphertext, Key, Nonce, Commitment, Tag)

			Expect(Plaintext).Never.ToBeNil()
			Expect(BytesEqual(Plaintext :: buffer, Message)).ToBe(true)
		end)
	end)

	Describe("Ciphertext Properties", function()
		Test("Ciphertext length equals plaintext length", function()
			local Key = RandomBytes(32)
			local Nonce = RandomBytes(32)

			for _, Length in { 0, 1, 15, 16, 17, 63, 64, 65, 127, 128, 129, 1000 } do
				local Message = RandomBytes(Length)
				local Ciphertext, _, _ = Arcturus.Encrypt(Message, Key, Nonce)
				Expect(buffer.len(Ciphertext)).ToBe(Length)
			end
		end)

		Test("Ciphertext differs from plaintext", function()
			local Key = RandomBytes(32)
			local Nonce = RandomBytes(32)
			local Message = buffer.fromstring("This is a test message for encryption")

			local Ciphertext, _, _ = Arcturus.Encrypt(Message, Key, Nonce)

			Expect(BytesEqual(Ciphertext, Message)).ToBe(false)
		end)

		Test("Commitment is 32 bytes", function()
			local Key = RandomBytes(32)
			local Nonce = RandomBytes(32)
			local Message = RandomBytes(100)

			local _, Commitment, _ = Arcturus.Encrypt(Message, Key, Nonce)

			Expect(buffer.len(Commitment)).ToBe(32)
		end)

		Test("Tag is 16 bytes", function()
			local Key = RandomBytes(32)
			local Nonce = RandomBytes(32)
			local Message = RandomBytes(100)

			local _, _, Tag = Arcturus.Encrypt(Message, Key, Nonce)

			Expect(buffer.len(Tag)).ToBe(16)
		end)
	end)

	Describe("Determinism", function()
		Test("Same inputs produce same outputs", function()
			local Key = RandomBytes(32)
			local Nonce = RandomBytes(32)
			local Message = buffer.fromstring("Determinism test")

			local Ciphertext1, Commitment1, Tag1 = Arcturus.Encrypt(Message, Key, Nonce)
			local Ciphertext2, Commitment2, Tag2 = Arcturus.Encrypt(Message, Key, Nonce)

			Expect(BytesEqual(Ciphertext1, Ciphertext2)).ToBe(true)
			Expect(BytesEqual(Commitment1, Commitment2)).ToBe(true)
			Expect(BytesEqual(Tag1, Tag2)).ToBe(true)
		end)

		Test("Different keys produce different ciphertexts", function()
			local Key1 = RandomBytes(32)
			local Key2 = RandomBytes(32)
			local Nonce = RandomBytes(32)
			local Message = buffer.fromstring("Key difference test")

			local Ciphertext1, Commitment1, Tag1 = Arcturus.Encrypt(Message, Key1, Nonce)
			local Ciphertext2, Commitment2, Tag2 = Arcturus.Encrypt(Message, Key2, Nonce)

			Expect(BytesEqual(Ciphertext1, Ciphertext2)).ToBe(false)
			Expect(BytesEqual(Commitment1, Commitment2)).ToBe(false)
			Expect(BytesEqual(Tag1, Tag2)).ToBe(false)
		end)

		Test("Different nonces produce different ciphertexts", function()
			local Key = RandomBytes(32)
			local Nonce1 = RandomBytes(32)
			local Nonce2 = RandomBytes(32)
			local Message = buffer.fromstring("Nonce difference test")

			local Ciphertext1, Commitment1, Tag1 = Arcturus.Encrypt(Message, Key, Nonce1)
			local Ciphertext2, Commitment2, Tag2 = Arcturus.Encrypt(Message, Key, Nonce2)

			Expect(BytesEqual(Ciphertext1, Ciphertext2)).ToBe(false)
			Expect(BytesEqual(Commitment1, Commitment2)).ToBe(false)
			Expect(BytesEqual(Tag1, Tag2)).ToBe(false)
		end)
	end)

	Describe("Authentication - Tamper Detection", function()
		Test("Detects tampered ciphertext (first byte)", function()
			local Key = RandomBytes(32)
			local Nonce = RandomBytes(32)
			local Message = buffer.fromstring("Tamper detection test")

			local Ciphertext, Commitment, Tag = Arcturus.Encrypt(Message, Key, Nonce)
			local Tampered = FlipBit(Ciphertext, 0, 0)

			local Plaintext = Arcturus.Decrypt(Tampered, Key, Nonce, Commitment, Tag)

			Expect(Plaintext).ToBeNil()
		end)

		Test("Detects tampered ciphertext (last byte)", function()
			local Key = RandomBytes(32)
			local Nonce = RandomBytes(32)
			local Message = buffer.fromstring("Tamper detection test")

			local Ciphertext, Commitment, Tag = Arcturus.Encrypt(Message, Key, Nonce)
			local Tampered = FlipBit(Ciphertext, buffer.len(Ciphertext) - 1, 0)

			local Plaintext = Arcturus.Decrypt(Tampered, Key, Nonce, Commitment, Tag)

			Expect(Plaintext).ToBeNil()
		end)

		Test("Detects tampered ciphertext (middle byte)", function()
			local Key = RandomBytes(32)
			local Nonce = RandomBytes(32)
			local Message = RandomBytes(100)

			local Ciphertext, Commitment, Tag = Arcturus.Encrypt(Message, Key, Nonce)
			local Tampered = FlipBit(Ciphertext, 50, 3)

			local Plaintext = Arcturus.Decrypt(Tampered, Key, Nonce, Commitment, Tag)

			Expect(Plaintext).ToBeNil()
		end)

		Test("Detects tampered tag (first byte)", function()
			local Key = RandomBytes(32)
			local Nonce = RandomBytes(32)
			local Message = buffer.fromstring("Tag tamper test")

			local Ciphertext, Commitment, Tag = Arcturus.Encrypt(Message, Key, Nonce)
			local TamperedTag = FlipBit(Tag, 0, 0)

			local Plaintext = Arcturus.Decrypt(Ciphertext, Key, Nonce, Commitment, TamperedTag)

			Expect(Plaintext).ToBeNil()
		end)

		Test("Detects tampered tag (last byte)", function()
			local Key = RandomBytes(32)
			local Nonce = RandomBytes(32)
			local Message = buffer.fromstring("Tag tamper test")

			local Ciphertext, Commitment, Tag = Arcturus.Encrypt(Message, Key, Nonce)
			local TamperedTag = FlipBit(Tag, 15, 7)

			local Plaintext = Arcturus.Decrypt(Ciphertext, Key, Nonce, Commitment, TamperedTag)

			Expect(Plaintext).ToBeNil()
		end)

		Test("Detects tampered commitment (first byte)", function()
			local Key = RandomBytes(32)
			local Nonce = RandomBytes(32)
			local Message = buffer.fromstring("Commitment tamper test")

			local Ciphertext, Commitment, Tag = Arcturus.Encrypt(Message, Key, Nonce)
			local TamperedCommitment = FlipBit(Commitment, 0, 0)

			local Plaintext = Arcturus.Decrypt(Ciphertext, Key, Nonce, TamperedCommitment, Tag)

			Expect(Plaintext).ToBeNil()
		end)

		Test("Detects tampered commitment (last byte)", function()
			local Key = RandomBytes(32)
			local Nonce = RandomBytes(32)
			local Message = buffer.fromstring("Commitment tamper test")

			local Ciphertext, Commitment, Tag = Arcturus.Encrypt(Message, Key, Nonce)
			local TamperedCommitment = FlipBit(Commitment, 31, 7)

			local Plaintext = Arcturus.Decrypt(Ciphertext, Key, Nonce, TamperedCommitment, Tag)

			Expect(Plaintext).ToBeNil()
		end)
	end)

	Describe("Key Commitment", function()
		Test("Wrong key fails decryption", function()
			local Key1 = RandomBytes(32)
			local Key2 = RandomBytes(32)
			local Nonce = RandomBytes(32)
			local Message = buffer.fromstring("Key commitment test")

			local Ciphertext, Commitment, Tag = Arcturus.Encrypt(Message, Key1, Nonce)
			local Plaintext = Arcturus.Decrypt(Ciphertext, Key2, Nonce, Commitment, Tag)

			Expect(Plaintext).ToBeNil()
		end)

		Test("Wrong nonce fails decryption", function()
			local Key = RandomBytes(32)
			local Nonce1 = RandomBytes(32)
			local Nonce2 = RandomBytes(32)
			local Message = buffer.fromstring("Nonce commitment test")

			local Ciphertext, Commitment, Tag = Arcturus.Encrypt(Message, Key, Nonce1)
			local Plaintext = Arcturus.Decrypt(Ciphertext, Key, Nonce2, Commitment, Tag)

			Expect(Plaintext).ToBeNil()
		end)

		Test("Commitment changes with key", function()
			local Key1 = RandomBytes(32)
			local Key2 = RandomBytes(32)
			local Nonce = RandomBytes(32)
			local Message = buffer.fromstring("Test")

			local _, Commitment1, _ = Arcturus.Encrypt(Message, Key1, Nonce)
			local _, Commitment2, _ = Arcturus.Encrypt(Message, Key2, Nonce)

			Expect(BytesEqual(Commitment1, Commitment2)).ToBe(false)
		end)

		Test("Commitment changes with nonce", function()
			local Key = RandomBytes(32)
			local Nonce1 = RandomBytes(32)
			local Nonce2 = RandomBytes(32)
			local Message = buffer.fromstring("Test")

			local _, Commitment1, _ = Arcturus.Encrypt(Message, Key, Nonce1)
			local _, Commitment2, _ = Arcturus.Encrypt(Message, Key, Nonce2)

			Expect(BytesEqual(Commitment1, Commitment2)).ToBe(false)
		end)
	end)

	Describe("AAD (Associated Authenticated Data)", function()
		Test("Encrypts and decrypts with AAD", function()
			local Key = RandomBytes(32)
			local Nonce = RandomBytes(32)
			local Message = buffer.fromstring("Message with AAD")
			local AAD = buffer.fromstring("Associated data")

			local Ciphertext, Commitment, Tag = Arcturus.Encrypt(Message, Key, Nonce, AAD)
			local Plaintext = Arcturus.Decrypt(Ciphertext, Key, Nonce, Commitment, Tag, AAD)

			Expect(Plaintext).Never.ToBeNil()
			Expect(buffer.tostring(Plaintext :: buffer)).ToBe("Message with AAD")
		end)

		Test("Decryption fails with wrong AAD", function()
			local Key = RandomBytes(32)
			local Nonce = RandomBytes(32)
			local Message = buffer.fromstring("Message with AAD")
			local AAD1 = buffer.fromstring("Associated data 1")
			local AAD2 = buffer.fromstring("Associated data 2")

			local Ciphertext, Commitment, Tag = Arcturus.Encrypt(Message, Key, Nonce, AAD1)
			local Plaintext = Arcturus.Decrypt(Ciphertext, Key, Nonce, Commitment, Tag, AAD2)

			Expect(Plaintext).ToBeNil()
		end)

		Test("Decryption fails with missing AAD", function()
			local Key = RandomBytes(32)
			local Nonce = RandomBytes(32)
			local Message = buffer.fromstring("Message with AAD")
			local AAD = buffer.fromstring("Associated data")

			local Ciphertext, Commitment, Tag = Arcturus.Encrypt(Message, Key, Nonce, AAD)
			local Plaintext = Arcturus.Decrypt(Ciphertext, Key, Nonce, Commitment, Tag)

			Expect(Plaintext).ToBeNil()
		end)

		Test("Decryption fails with extra AAD", function()
			local Key = RandomBytes(32)
			local Nonce = RandomBytes(32)
			local Message = buffer.fromstring("Message without AAD")

			local Ciphertext, Commitment, Tag = Arcturus.Encrypt(Message, Key, Nonce)
			local AAD = buffer.fromstring("Extra AAD")
			local Plaintext = Arcturus.Decrypt(Ciphertext, Key, Nonce, Commitment, Tag, AAD)

			Expect(Plaintext).ToBeNil()
		end)

		Test("Empty AAD works correctly", function()
			local Key = RandomBytes(32)
			local Nonce = RandomBytes(32)
			local Message = buffer.fromstring("Message with empty AAD")
			local AAD = buffer.create(0)

			local Ciphertext, Commitment, Tag = Arcturus.Encrypt(Message, Key, Nonce, AAD)
			local Plaintext = Arcturus.Decrypt(Ciphertext, Key, Nonce, Commitment, Tag, AAD)

			Expect(Plaintext).Never.ToBeNil()
			Expect(buffer.tostring(Plaintext :: buffer)).ToBe("Message with empty AAD")
		end)

		Test("Large AAD works correctly", function()
			local Key = RandomBytes(32)
			local Nonce = RandomBytes(32)
			local Message = buffer.fromstring("Message with large AAD")
			local AAD = RandomBytes(10000)

			local Ciphertext, Commitment, Tag = Arcturus.Encrypt(Message, Key, Nonce, AAD)
			local Plaintext = Arcturus.Decrypt(Ciphertext, Key, Nonce, Commitment, Tag, AAD)

			Expect(Plaintext).Never.ToBeNil()
			Expect(buffer.tostring(Plaintext :: buffer)).ToBe("Message with large AAD")
		end)

		Test("AAD does not affect ciphertext content", function()
			local Key = RandomBytes(32)
			local Nonce = RandomBytes(32)
			local Message = buffer.fromstring("Same message")
			local AAD1 = buffer.fromstring("AAD 1")
			local AAD2 = buffer.fromstring("AAD 2")

			local Ciphertext1, _, _ = Arcturus.Encrypt(Message, Key, Nonce, AAD1)
			local Ciphertext2, _, _ = Arcturus.Encrypt(Message, Key, Nonce, AAD2)

			Expect(BytesEqual(Ciphertext1, Ciphertext2)).ToBe(true)
		end)

		Test("AAD affects tag", function()
			local Key = RandomBytes(32)
			local Nonce = RandomBytes(32)
			local Message = buffer.fromstring("Same message")
			local AAD1 = buffer.fromstring("AAD 1")
			local AAD2 = buffer.fromstring("AAD 2")

			local _, _, Tag1 = Arcturus.Encrypt(Message, Key, Nonce, AAD1)
			local _, _, Tag2 = Arcturus.Encrypt(Message, Key, Nonce, AAD2)

			Expect(BytesEqual(Tag1, Tag2)).ToBe(false)
		end)
	end)

	Describe("Input Validation", function()
		Test("Rejects wrong key size (too short)", function()
			local Key = RandomBytes(16)
			local Nonce = RandomBytes(32)
			local Message = buffer.fromstring("Test")

			Expect(function()
				Arcturus.Encrypt(Message, Key, Nonce)
			end).ToThrow("Key must be exactly 32 bytes")
		end)

		Test("Rejects wrong key size (too long)", function()
			local Key = RandomBytes(64)
			local Nonce = RandomBytes(32)
			local Message = buffer.fromstring("Test")

			Expect(function()
				Arcturus.Encrypt(Message, Key, Nonce)
			end).ToThrow("Key must be exactly 32 bytes")
		end)

		Test("Rejects wrong nonce size (too short)", function()
			local Key = RandomBytes(32)
			local Nonce = RandomBytes(12)
			local Message = buffer.fromstring("Test")

			Expect(function()
				Arcturus.Encrypt(Message, Key, Nonce)
			end).ToThrow("Nonce must be exactly 32 bytes")
		end)

		Test("Rejects wrong nonce size (too long)", function()
			local Key = RandomBytes(32)
			local Nonce = RandomBytes(64)
			local Message = buffer.fromstring("Test")

			Expect(function()
				Arcturus.Encrypt(Message, Key, Nonce)
			end).ToThrow("Nonce must be exactly 32 bytes")
		end)

		Test("Decrypt rejects wrong commitment size", function()
			local Key = RandomBytes(32)
			local Nonce = RandomBytes(32)
			local Ciphertext = RandomBytes(32)
			local Commitment = RandomBytes(16)
			local Tag = RandomBytes(16)

			Expect(function()
				Arcturus.Decrypt(Ciphertext, Key, Nonce, Commitment, Tag)
			end).ToThrow("Commitment must be exactly 32 bytes")
		end)

		Test("Decrypt rejects wrong tag size", function()
			local Key = RandomBytes(32)
			local Nonce = RandomBytes(32)
			local Ciphertext = RandomBytes(32)
			local Commitment = RandomBytes(32)
			local Tag = RandomBytes(32)

			Expect(function()
				Arcturus.Decrypt(Ciphertext, Key, Nonce, Commitment, Tag)
			end).ToThrow("Tag must be exactly 16 bytes")
		end)
	end)

	Describe("Edge Cases", function()
		Test("All-zero key works", function()
			local Key = ZeroBytes(32)
			local Nonce = RandomBytes(32)
			local Message = buffer.fromstring("Zero key test")

			local Ciphertext, Commitment, Tag = Arcturus.Encrypt(Message, Key, Nonce)
			local Plaintext = Arcturus.Decrypt(Ciphertext, Key, Nonce, Commitment, Tag)

			Expect(Plaintext).Never.ToBeNil()
			Expect(buffer.tostring(Plaintext :: buffer)).ToBe("Zero key test")
		end)

		Test("All-zero nonce works", function()
			local Key = RandomBytes(32)
			local Nonce = ZeroBytes(32)
			local Message = buffer.fromstring("Zero nonce test")

			local Ciphertext, Commitment, Tag = Arcturus.Encrypt(Message, Key, Nonce)
			local Plaintext = Arcturus.Decrypt(Ciphertext, Key, Nonce, Commitment, Tag)

			Expect(Plaintext).Never.ToBeNil()
			Expect(buffer.tostring(Plaintext :: buffer)).ToBe("Zero nonce test")
		end)

		Test("All-zero message encrypts correctly", function()
			local Key = RandomBytes(32)
			local Nonce = RandomBytes(32)
			local Message = ZeroBytes(64)

			local Ciphertext, Commitment, Tag = Arcturus.Encrypt(Message, Key, Nonce)
			local Plaintext = Arcturus.Decrypt(Ciphertext, Key, Nonce, Commitment, Tag)

			Expect(Plaintext).Never.ToBeNil()
			Expect(BytesEqual(Plaintext :: buffer, Message)).ToBe(true)
		end)

		Test("All-0xFF message encrypts correctly", function()
			local Key = RandomBytes(32)
			local Nonce = RandomBytes(32)
			local Message = buffer.create(64)
			for Index = 0, 63 do
				buffer.writeu8(Message, Index, 0xFF)
			end

			local Ciphertext, Commitment, Tag = Arcturus.Encrypt(Message, Key, Nonce)
			local Plaintext = Arcturus.Decrypt(Ciphertext, Key, Nonce, Commitment, Tag)

			Expect(Plaintext).Never.ToBeNil()
			Expect(BytesEqual(Plaintext :: buffer, Message)).ToBe(true)
		end)

		Test("Block boundary - 63 bytes", function()
			local Key = RandomBytes(32)
			local Nonce = RandomBytes(32)
			local Message = RandomBytes(63)

			local Ciphertext, Commitment, Tag = Arcturus.Encrypt(Message, Key, Nonce)
			local Plaintext = Arcturus.Decrypt(Ciphertext, Key, Nonce, Commitment, Tag)

			Expect(Plaintext).Never.ToBeNil()
			Expect(BytesEqual(Plaintext :: buffer, Message)).ToBe(true)
		end)

		Test("Block boundary - 64 bytes", function()
			local Key = RandomBytes(32)
			local Nonce = RandomBytes(32)
			local Message = RandomBytes(64)

			local Ciphertext, Commitment, Tag = Arcturus.Encrypt(Message, Key, Nonce)
			local Plaintext = Arcturus.Decrypt(Ciphertext, Key, Nonce, Commitment, Tag)

			Expect(Plaintext).Never.ToBeNil()
			Expect(BytesEqual(Plaintext :: buffer, Message)).ToBe(true)
		end)

		Test("Block boundary - 127 bytes", function()
			local Key = RandomBytes(32)
			local Nonce = RandomBytes(32)
			local Message = RandomBytes(127)

			local Ciphertext, Commitment, Tag = Arcturus.Encrypt(Message, Key, Nonce)
			local Plaintext = Arcturus.Decrypt(Ciphertext, Key, Nonce, Commitment, Tag)

			Expect(Plaintext).Never.ToBeNil()
			Expect(BytesEqual(Plaintext :: buffer, Message)).ToBe(true)
		end)

		Test("Block boundary - 128 bytes", function()
			local Key = RandomBytes(32)
			local Nonce = RandomBytes(32)
			local Message = RandomBytes(128)

			local Ciphertext, Commitment, Tag = Arcturus.Encrypt(Message, Key, Nonce)
			local Plaintext = Arcturus.Decrypt(Ciphertext, Key, Nonce, Commitment, Tag)

			Expect(Plaintext).Never.ToBeNil()
			Expect(BytesEqual(Plaintext :: buffer, Message)).ToBe(true)
		end)

		Test("Multiple blocks with partial last block", function()
			local Key = RandomBytes(32)
			local Nonce = RandomBytes(32)
			local Message = RandomBytes(200)

			local Ciphertext, Commitment, Tag = Arcturus.Encrypt(Message, Key, Nonce)
			local Plaintext = Arcturus.Decrypt(Ciphertext, Key, Nonce, Commitment, Tag)

			Expect(Plaintext).Never.ToBeNil()
			Expect(BytesEqual(Plaintext :: buffer, Message)).ToBe(true)
		end)
	end)

	Describe("Stress Tests", function()
		Test("Many sequential encrypt/decrypt operations", function()
			local Key = RandomBytes(32)
			local Nonce = RandomBytes(32)

			for Iteration = 1, 100 do
				local Message = RandomBytes(Iteration)
				local Ciphertext, Commitment, Tag = Arcturus.Encrypt(Message, Key, Nonce)
				local Plaintext = Arcturus.Decrypt(Ciphertext, Key, Nonce, Commitment, Tag)

				Expect(Plaintext).Never.ToBeNil()
				Expect(BytesEqual(Plaintext :: buffer, Message)).ToBe(true)
			end
		end)

		Test("Random keys and nonces", function()
			for _ = 1, 50 do
				local Key = RandomBytes(32)
				local Nonce = RandomBytes(32)
				local Message = RandomBytes(math.random(1, 500))

				local Ciphertext, Commitment, Tag = Arcturus.Encrypt(Message, Key, Nonce)
				local Plaintext = Arcturus.Decrypt(Ciphertext, Key, Nonce, Commitment, Tag)

				Expect(Plaintext).Never.ToBeNil()
				Expect(BytesEqual(Plaintext :: buffer, Message)).ToBe(true)
			end
		end)
	end)

	Describe("Known Answer Tests", function()
		Test("Zero key, zero nonce produces consistent output", function()
			local Key = ZeroBytes(32)
			local Nonce = ZeroBytes(32)
			local Message = ZeroBytes(32)

			local Ciphertext1, Commitment1, Tag1 = Arcturus.Encrypt(Message, Key, Nonce)
			local Ciphertext2, Commitment2, Tag2 = Arcturus.Encrypt(Message, Key, Nonce)

			Expect(BufferToHex(Ciphertext1)).ToBe(BufferToHex(Ciphertext2))
			Expect(BufferToHex(Commitment1)).ToBe(BufferToHex(Commitment2))
			Expect(BufferToHex(Tag1)).ToBe(BufferToHex(Tag2))
		end)

		Test("Ciphertext is not all zeros for zero plaintext", function()
			local Key = RandomBytes(32)
			local Nonce = RandomBytes(32)
			local Message = ZeroBytes(64)

			local Ciphertext, _, _ = Arcturus.Encrypt(Message, Key, Nonce)

			local AllZeros = true
			for Index = 0, buffer.len(Ciphertext) - 1 do
				if buffer.readu8(Ciphertext, Index) ~= 0 then
					AllZeros = false
					break
				end
			end

			Expect(AllZeros).ToBe(false)
		end)
	end)
end)

return 1