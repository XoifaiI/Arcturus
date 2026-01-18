--[=[
	Cryptography library: Arcturus AEAD
	
	A high performance AEAD combining ARX based KDF and stream cipher
	with Poly1305 authentication.
	
	Sizes:
		Key: 32 bytes
		Nonce: 32 bytes
		Commitment: 32 bytes
		Tag: 16 bytes
		Overhead: 48 bytes

	Return type: (buffer, buffer, buffer) for Encrypt, buffer? for Decrypt
	Example usage:
		local Message = buffer.fromstring("Hello World")
		local Key = CSPRNG.RandomBytes(32)
		local Nonce = CSPRNG.RandomBytes(32)
		local AAD = buffer.fromstring("metadata")
		
		local Ciphertext, Commitment, Tag = Arcturus.Encrypt(Message, Key, Nonce, AAD)
		local Plaintext = Arcturus.Decrypt(Ciphertext, Key, Nonce, Commitment, Tag, AAD)
--]=]

--!strict
--!optimize 2
--!native

local Poly1305 = require("@self/Poly1305")

local Arcturus = {}

local KEY_SIZE = 32
local NONCE_SIZE = 32
local COMMITMENT_SIZE = 32
local TAG_SIZE = 16
local MASK = 0xFFFFFFFF

local IV0, IV1, IV2, IV3 = 0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A
local IV4, IV5, IV6, IV7 = 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19

local FLAG_KDF = 0x01
local FLAG_COMMIT = 0x02
local FLAG_STREAM = 0x04

local KEYSTREAM_BUFFER = buffer.create(64)
local AUTH_KEY_BUFFER = buffer.create(32)
local COMMITMENT_BUFFER = buffer.create(32)

local function DeriveKeys(Key: buffer, Nonce: buffer): (
	number, number, number, number, number, number, number, number,
	buffer, buffer, number, number
	)
	local K0 = buffer.readu32(Key, 0)
	local K1 = buffer.readu32(Key, 4)
	local K2 = buffer.readu32(Key, 8)
	local K3 = buffer.readu32(Key, 12)
	local K4 = buffer.readu32(Key, 16)
	local K5 = buffer.readu32(Key, 20)
	local K6 = buffer.readu32(Key, 24)
	local K7 = buffer.readu32(Key, 28)

	local N0 = buffer.readu32(Nonce, 0)
	local N1 = buffer.readu32(Nonce, 4)
	local N2 = buffer.readu32(Nonce, 8)
	local N3 = buffer.readu32(Nonce, 12)
	local N4 = buffer.readu32(Nonce, 16)
	local N5 = buffer.readu32(Nonce, 20)
	local N6 = buffer.readu32(Nonce, 24)
	local N7 = buffer.readu32(Nonce, 28)

	local V0, V1, V2, V3 = K0, K1, K2, K3
	local V4, V5, V6, V7 = K4, K5, K6, K7
	local V8, V9, V10, V11 = IV0, IV1, IV2, IV3
	local V12, V13, V14, V15 = 0, 0, 32, FLAG_KDF

	local M0, M1, M2, M3, M4, M5, M6, M7 = N0, N1, N2, N3, N4, N5, N6, N7
	local M8, M9, M10, M11, M12, M13, M14, M15 = 0, 0, 0, 0, 0, 0, 0, 0

	for Round = 1, 8 do
		V0 = bit32.band(V0 + V4 + M0, MASK); V12 = bit32.rrotate(bit32.bxor(V12, V0), 16)
		V8 = bit32.band(V8 + V12, MASK); V4 = bit32.rrotate(bit32.bxor(V4, V8), 12)
		V0 = bit32.band(V0 + V4 + M1, MASK); V12 = bit32.rrotate(bit32.bxor(V12, V0), 8)
		V8 = bit32.band(V8 + V12, MASK); V4 = bit32.rrotate(bit32.bxor(V4, V8), 7)

		V1 = bit32.band(V1 + V5 + M2, MASK); V13 = bit32.rrotate(bit32.bxor(V13, V1), 16)
		V9 = bit32.band(V9 + V13, MASK); V5 = bit32.rrotate(bit32.bxor(V5, V9), 12)
		V1 = bit32.band(V1 + V5 + M3, MASK); V13 = bit32.rrotate(bit32.bxor(V13, V1), 8)
		V9 = bit32.band(V9 + V13, MASK); V5 = bit32.rrotate(bit32.bxor(V5, V9), 7)

		V2 = bit32.band(V2 + V6 + M4, MASK); V14 = bit32.rrotate(bit32.bxor(V14, V2), 16)
		V10 = bit32.band(V10 + V14, MASK); V6 = bit32.rrotate(bit32.bxor(V6, V10), 12)
		V2 = bit32.band(V2 + V6 + M5, MASK); V14 = bit32.rrotate(bit32.bxor(V14, V2), 8)
		V10 = bit32.band(V10 + V14, MASK); V6 = bit32.rrotate(bit32.bxor(V6, V10), 7)

		V3 = bit32.band(V3 + V7 + M6, MASK); V15 = bit32.rrotate(bit32.bxor(V15, V3), 16)
		V11 = bit32.band(V11 + V15, MASK); V7 = bit32.rrotate(bit32.bxor(V7, V11), 12)
		V3 = bit32.band(V3 + V7 + M7, MASK); V15 = bit32.rrotate(bit32.bxor(V15, V3), 8)
		V11 = bit32.band(V11 + V15, MASK); V7 = bit32.rrotate(bit32.bxor(V7, V11), 7)

		V0 = bit32.band(V0 + V5 + M8, MASK); V15 = bit32.rrotate(bit32.bxor(V15, V0), 16)
		V10 = bit32.band(V10 + V15, MASK); V5 = bit32.rrotate(bit32.bxor(V5, V10), 12)
		V0 = bit32.band(V0 + V5 + M9, MASK); V15 = bit32.rrotate(bit32.bxor(V15, V0), 8)
		V10 = bit32.band(V10 + V15, MASK); V5 = bit32.rrotate(bit32.bxor(V5, V10), 7)

		V1 = bit32.band(V1 + V6 + M10, MASK); V12 = bit32.rrotate(bit32.bxor(V12, V1), 16)
		V11 = bit32.band(V11 + V12, MASK); V6 = bit32.rrotate(bit32.bxor(V6, V11), 12)
		V1 = bit32.band(V1 + V6 + M11, MASK); V12 = bit32.rrotate(bit32.bxor(V12, V1), 8)
		V11 = bit32.band(V11 + V12, MASK); V6 = bit32.rrotate(bit32.bxor(V6, V11), 7)

		V2 = bit32.band(V2 + V7 + M12, MASK); V13 = bit32.rrotate(bit32.bxor(V13, V2), 16)
		V8 = bit32.band(V8 + V13, MASK); V7 = bit32.rrotate(bit32.bxor(V7, V8), 12)
		V2 = bit32.band(V2 + V7 + M13, MASK); V13 = bit32.rrotate(bit32.bxor(V13, V2), 8)
		V8 = bit32.band(V8 + V13, MASK); V7 = bit32.rrotate(bit32.bxor(V7, V8), 7)

		V3 = bit32.band(V3 + V4 + M14, MASK); V14 = bit32.rrotate(bit32.bxor(V14, V3), 16)
		V9 = bit32.band(V9 + V14, MASK); V4 = bit32.rrotate(bit32.bxor(V4, V9), 12)
		V3 = bit32.band(V3 + V4 + M15, MASK); V14 = bit32.rrotate(bit32.bxor(V14, V3), 8)
		V9 = bit32.band(V9 + V14, MASK); V4 = bit32.rrotate(bit32.bxor(V4, V9), 7)

		if Round ~= 8 then
			M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15 =
				M2, M6, M3, M10, M7, M0, M4, M13, M1, M11, M12, M5, M9, M14, M15, M8
		end
	end

	local E0, E1, E2, E3 = bit32.bxor(V0, V8), bit32.bxor(V1, V9), bit32.bxor(V2, V10), bit32.bxor(V3, V11)
	local E4, E5, E6, E7 = bit32.bxor(V4, V12), bit32.bxor(V5, V13), bit32.bxor(V6, V14), bit32.bxor(V7, V15)

	V0, V1, V2, V3 = E0, E1, E2, E3
	V4, V5, V6, V7 = E4, E5, E6, E7
	V8, V9, V10, V11 = IV0, IV1, IV2, IV3
	V12, V13, V14, V15 = 1, 0, 32, FLAG_COMMIT

	M0, M1, M2, M3, M4, M5, M6, M7 = N0, N1, N2, N3, N4, N5, N6, N7
	M8, M9, M10, M11, M12, M13, M14, M15 = 0, 0, 0, 0, 0, 0, 0, 0

	for Round = 1, 8 do
		V0 = bit32.band(V0 + V4 + M0, MASK); V12 = bit32.rrotate(bit32.bxor(V12, V0), 16)
		V8 = bit32.band(V8 + V12, MASK); V4 = bit32.rrotate(bit32.bxor(V4, V8), 12)
		V0 = bit32.band(V0 + V4 + M1, MASK); V12 = bit32.rrotate(bit32.bxor(V12, V0), 8)
		V8 = bit32.band(V8 + V12, MASK); V4 = bit32.rrotate(bit32.bxor(V4, V8), 7)

		V1 = bit32.band(V1 + V5 + M2, MASK); V13 = bit32.rrotate(bit32.bxor(V13, V1), 16)
		V9 = bit32.band(V9 + V13, MASK); V5 = bit32.rrotate(bit32.bxor(V5, V9), 12)
		V1 = bit32.band(V1 + V5 + M3, MASK); V13 = bit32.rrotate(bit32.bxor(V13, V1), 8)
		V9 = bit32.band(V9 + V13, MASK); V5 = bit32.rrotate(bit32.bxor(V5, V9), 7)

		V2 = bit32.band(V2 + V6 + M4, MASK); V14 = bit32.rrotate(bit32.bxor(V14, V2), 16)
		V10 = bit32.band(V10 + V14, MASK); V6 = bit32.rrotate(bit32.bxor(V6, V10), 12)
		V2 = bit32.band(V2 + V6 + M5, MASK); V14 = bit32.rrotate(bit32.bxor(V14, V2), 8)
		V10 = bit32.band(V10 + V14, MASK); V6 = bit32.rrotate(bit32.bxor(V6, V10), 7)

		V3 = bit32.band(V3 + V7 + M6, MASK); V15 = bit32.rrotate(bit32.bxor(V15, V3), 16)
		V11 = bit32.band(V11 + V15, MASK); V7 = bit32.rrotate(bit32.bxor(V7, V11), 12)
		V3 = bit32.band(V3 + V7 + M7, MASK); V15 = bit32.rrotate(bit32.bxor(V15, V3), 8)
		V11 = bit32.band(V11 + V15, MASK); V7 = bit32.rrotate(bit32.bxor(V7, V11), 7)

		V0 = bit32.band(V0 + V5 + M8, MASK); V15 = bit32.rrotate(bit32.bxor(V15, V0), 16)
		V10 = bit32.band(V10 + V15, MASK); V5 = bit32.rrotate(bit32.bxor(V5, V10), 12)
		V0 = bit32.band(V0 + V5 + M9, MASK); V15 = bit32.rrotate(bit32.bxor(V15, V0), 8)
		V10 = bit32.band(V10 + V15, MASK); V5 = bit32.rrotate(bit32.bxor(V5, V10), 7)

		V1 = bit32.band(V1 + V6 + M10, MASK); V12 = bit32.rrotate(bit32.bxor(V12, V1), 16)
		V11 = bit32.band(V11 + V12, MASK); V6 = bit32.rrotate(bit32.bxor(V6, V11), 12)
		V1 = bit32.band(V1 + V6 + M11, MASK); V12 = bit32.rrotate(bit32.bxor(V12, V1), 8)
		V11 = bit32.band(V11 + V12, MASK); V6 = bit32.rrotate(bit32.bxor(V6, V11), 7)

		V2 = bit32.band(V2 + V7 + M12, MASK); V13 = bit32.rrotate(bit32.bxor(V13, V2), 16)
		V8 = bit32.band(V8 + V13, MASK); V7 = bit32.rrotate(bit32.bxor(V7, V8), 12)
		V2 = bit32.band(V2 + V7 + M13, MASK); V13 = bit32.rrotate(bit32.bxor(V13, V2), 8)
		V8 = bit32.band(V8 + V13, MASK); V7 = bit32.rrotate(bit32.bxor(V7, V8), 7)

		V3 = bit32.band(V3 + V4 + M14, MASK); V14 = bit32.rrotate(bit32.bxor(V14, V3), 16)
		V9 = bit32.band(V9 + V14, MASK); V4 = bit32.rrotate(bit32.bxor(V4, V9), 12)
		V3 = bit32.band(V3 + V4 + M15, MASK); V14 = bit32.rrotate(bit32.bxor(V14, V3), 8)
		V9 = bit32.band(V9 + V14, MASK); V4 = bit32.rrotate(bit32.bxor(V4, V9), 7)

		if Round ~= 8 then
			M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15 =
				M2, M6, M3, M10, M7, M0, M4, M13, M1, M11, M12, M5, M9, M14, M15, M8
		end
	end

	local Commitment = COMMITMENT_BUFFER
	buffer.writeu32(Commitment, 0, bit32.bxor(V0, V8))
	buffer.writeu32(Commitment, 4, bit32.bxor(V1, V9))
	buffer.writeu32(Commitment, 8, bit32.bxor(V2, V10))
	buffer.writeu32(Commitment, 12, bit32.bxor(V3, V11))
	buffer.writeu32(Commitment, 16, bit32.bxor(V4, V12))
	buffer.writeu32(Commitment, 20, bit32.bxor(V5, V13))
	buffer.writeu32(Commitment, 24, bit32.bxor(V6, V14))
	buffer.writeu32(Commitment, 28, bit32.bxor(V7, V15))

	local AuthKey = AUTH_KEY_BUFFER
	buffer.writeu32(AuthKey, 0, V0)
	buffer.writeu32(AuthKey, 4, V1)
	buffer.writeu32(AuthKey, 8, V2)
	buffer.writeu32(AuthKey, 12, V3)
	buffer.writeu32(AuthKey, 16, V4)
	buffer.writeu32(AuthKey, 20, V5)
	buffer.writeu32(AuthKey, 24, V6)
	buffer.writeu32(AuthKey, 28, V7)

	return E0, E1, E2, E3, E4, E5, E6, E7, Commitment, AuthKey, N0, N1
end

local function ConstructAuthData(AAD: buffer, Commitment: buffer, Ciphertext: buffer): buffer
	local AADLength = buffer.len(AAD)
	local CiphertextLength = buffer.len(Ciphertext)
	local CombinedAADLength = AADLength + COMMITMENT_SIZE

	local AADPadding = (-CombinedAADLength) % 16
	local CiphertextPadding = (-CiphertextLength) % 16

	local TotalSize = CombinedAADLength + AADPadding + CiphertextLength + CiphertextPadding + 16
	local AuthData = buffer.create(TotalSize)
	local Offset = 0

	buffer.copy(AuthData, Offset, AAD, 0, AADLength)
	Offset += AADLength

	buffer.copy(AuthData, Offset, Commitment, 0, COMMITMENT_SIZE)
	Offset += COMMITMENT_SIZE + AADPadding

	buffer.copy(AuthData, Offset, Ciphertext, 0, CiphertextLength)
	Offset += CiphertextLength + CiphertextPadding

	buffer.writeu32(AuthData, Offset, CombinedAADLength)
	buffer.writeu32(AuthData, Offset + 8, CiphertextLength)

	return AuthData
end

local function ConstantTimeCompare(BufferA: buffer, BufferB: buffer): boolean
	local LengthA = buffer.len(BufferA)
	local LengthB = buffer.len(BufferB)
	if LengthA ~= LengthB then
		return false
	end

	local Difference = 0
	for Index = 0, LengthA - 1 do
		Difference = bit32.bor(Difference, bit32.bxor(
			buffer.readu8(BufferA, Index),
			buffer.readu8(BufferB, Index)
			))
	end

	return Difference == 0
end

function Arcturus.Encrypt(Message: buffer, Key: buffer, Nonce: buffer, AAD: buffer?): (buffer, buffer, buffer)
	if buffer.len(Key) ~= KEY_SIZE then
		error(`Key must be exactly {KEY_SIZE} bytes`, 2)
	end
	if buffer.len(Nonce) ~= NONCE_SIZE then
		error(`Nonce must be exactly {NONCE_SIZE} bytes`, 2)
	end

	local AAD = AAD or buffer.create(0)
	local MsgLen = buffer.len(Message)

	local K0, K1, K2, K3, K4, K5, K6, K7, CommitmentInternal, AuthKey, N0, N1 = DeriveKeys(Key, Nonce)

	local Commitment = buffer.create(32)
	buffer.copy(Commitment, 0, CommitmentInternal, 0, 32)

	local AuthKeyCopy = buffer.create(32)
	buffer.copy(AuthKeyCopy, 0, AuthKey, 0, 32)

	local Ciphertext = buffer.create(MsgLen)
	local FullBlocks = MsgLen // 64
	local KeystreamBuffer = KEYSTREAM_BUFFER

	for Block = 0, FullBlocks - 1 do
		local Counter = Block + 1
		local V0, V1, V2, V3 = K0, K1, K2, K3
		local V4, V5, V6, V7 = K4, K5, K6, K7
		local V8, V9, V10, V11 = IV0, IV1, IV2, IV3
		local V12, V13, V14, V15 = Counter, N0, N1, FLAG_STREAM

		for _ = 1, 8 do
			V0 = bit32.band(V0 + V4, MASK); V12 = bit32.rrotate(bit32.bxor(V12, V0), 16)
			V8 = bit32.band(V8 + V12, MASK); V4 = bit32.rrotate(bit32.bxor(V4, V8), 12)
			V0 = bit32.band(V0 + V4, MASK); V12 = bit32.rrotate(bit32.bxor(V12, V0), 8)
			V8 = bit32.band(V8 + V12, MASK); V4 = bit32.rrotate(bit32.bxor(V4, V8), 7)

			V1 = bit32.band(V1 + V5, MASK); V13 = bit32.rrotate(bit32.bxor(V13, V1), 16)
			V9 = bit32.band(V9 + V13, MASK); V5 = bit32.rrotate(bit32.bxor(V5, V9), 12)
			V1 = bit32.band(V1 + V5, MASK); V13 = bit32.rrotate(bit32.bxor(V13, V1), 8)
			V9 = bit32.band(V9 + V13, MASK); V5 = bit32.rrotate(bit32.bxor(V5, V9), 7)

			V2 = bit32.band(V2 + V6, MASK); V14 = bit32.rrotate(bit32.bxor(V14, V2), 16)
			V10 = bit32.band(V10 + V14, MASK); V6 = bit32.rrotate(bit32.bxor(V6, V10), 12)
			V2 = bit32.band(V2 + V6, MASK); V14 = bit32.rrotate(bit32.bxor(V14, V2), 8)
			V10 = bit32.band(V10 + V14, MASK); V6 = bit32.rrotate(bit32.bxor(V6, V10), 7)

			V3 = bit32.band(V3 + V7, MASK); V15 = bit32.rrotate(bit32.bxor(V15, V3), 16)
			V11 = bit32.band(V11 + V15, MASK); V7 = bit32.rrotate(bit32.bxor(V7, V11), 12)
			V3 = bit32.band(V3 + V7, MASK); V15 = bit32.rrotate(bit32.bxor(V15, V3), 8)
			V11 = bit32.band(V11 + V15, MASK); V7 = bit32.rrotate(bit32.bxor(V7, V11), 7)

			V0 = bit32.band(V0 + V5, MASK); V15 = bit32.rrotate(bit32.bxor(V15, V0), 16)
			V10 = bit32.band(V10 + V15, MASK); V5 = bit32.rrotate(bit32.bxor(V5, V10), 12)
			V0 = bit32.band(V0 + V5, MASK); V15 = bit32.rrotate(bit32.bxor(V15, V0), 8)
			V10 = bit32.band(V10 + V15, MASK); V5 = bit32.rrotate(bit32.bxor(V5, V10), 7)

			V1 = bit32.band(V1 + V6, MASK); V12 = bit32.rrotate(bit32.bxor(V12, V1), 16)
			V11 = bit32.band(V11 + V12, MASK); V6 = bit32.rrotate(bit32.bxor(V6, V11), 12)
			V1 = bit32.band(V1 + V6, MASK); V12 = bit32.rrotate(bit32.bxor(V12, V1), 8)
			V11 = bit32.band(V11 + V12, MASK); V6 = bit32.rrotate(bit32.bxor(V6, V11), 7)

			V2 = bit32.band(V2 + V7, MASK); V13 = bit32.rrotate(bit32.bxor(V13, V2), 16)
			V8 = bit32.band(V8 + V13, MASK); V7 = bit32.rrotate(bit32.bxor(V7, V8), 12)
			V2 = bit32.band(V2 + V7, MASK); V13 = bit32.rrotate(bit32.bxor(V13, V2), 8)
			V8 = bit32.band(V8 + V13, MASK); V7 = bit32.rrotate(bit32.bxor(V7, V8), 7)

			V3 = bit32.band(V3 + V4, MASK); V14 = bit32.rrotate(bit32.bxor(V14, V3), 16)
			V9 = bit32.band(V9 + V14, MASK); V4 = bit32.rrotate(bit32.bxor(V4, V9), 12)
			V3 = bit32.band(V3 + V4, MASK); V14 = bit32.rrotate(bit32.bxor(V14, V3), 8)
			V9 = bit32.band(V9 + V14, MASK); V4 = bit32.rrotate(bit32.bxor(V4, V9), 7)
		end

		local Off = Block * 64
		buffer.writeu32(Ciphertext, Off, bit32.bxor(buffer.readu32(Message, Off), bit32.band(V0 + K0, MASK)))
		buffer.writeu32(Ciphertext, Off + 4, bit32.bxor(buffer.readu32(Message, Off + 4), bit32.band(V1 + K1, MASK)))
		buffer.writeu32(Ciphertext, Off + 8, bit32.bxor(buffer.readu32(Message, Off + 8), bit32.band(V2 + K2, MASK)))
		buffer.writeu32(Ciphertext, Off + 12, bit32.bxor(buffer.readu32(Message, Off + 12), bit32.band(V3 + K3, MASK)))
		buffer.writeu32(Ciphertext, Off + 16, bit32.bxor(buffer.readu32(Message, Off + 16), bit32.band(V4 + K4, MASK)))
		buffer.writeu32(Ciphertext, Off + 20, bit32.bxor(buffer.readu32(Message, Off + 20), bit32.band(V5 + K5, MASK)))
		buffer.writeu32(Ciphertext, Off + 24, bit32.bxor(buffer.readu32(Message, Off + 24), bit32.band(V6 + K6, MASK)))
		buffer.writeu32(Ciphertext, Off + 28, bit32.bxor(buffer.readu32(Message, Off + 28), bit32.band(V7 + K7, MASK)))
		buffer.writeu32(Ciphertext, Off + 32, bit32.bxor(buffer.readu32(Message, Off + 32), bit32.band(V8 + IV0, MASK)))
		buffer.writeu32(Ciphertext, Off + 36, bit32.bxor(buffer.readu32(Message, Off + 36), bit32.band(V9 + IV1, MASK)))
		buffer.writeu32(Ciphertext, Off + 40, bit32.bxor(buffer.readu32(Message, Off + 40), bit32.band(V10 + IV2, MASK)))
		buffer.writeu32(Ciphertext, Off + 44, bit32.bxor(buffer.readu32(Message, Off + 44), bit32.band(V11 + IV3, MASK)))
		buffer.writeu32(Ciphertext, Off + 48, bit32.bxor(buffer.readu32(Message, Off + 48), bit32.band(V12 + Counter, MASK)))
		buffer.writeu32(Ciphertext, Off + 52, bit32.bxor(buffer.readu32(Message, Off + 52), bit32.band(V13 + N0, MASK)))
		buffer.writeu32(Ciphertext, Off + 56, bit32.bxor(buffer.readu32(Message, Off + 56), bit32.band(V14 + N1, MASK)))
		buffer.writeu32(Ciphertext, Off + 60, bit32.bxor(buffer.readu32(Message, Off + 60), bit32.band(V15 + FLAG_STREAM, MASK)))
	end

	local Remaining = MsgLen - FullBlocks * 64
	if Remaining > 0 then
		local Counter = FullBlocks + 1
		local V0, V1, V2, V3 = K0, K1, K2, K3
		local V4, V5, V6, V7 = K4, K5, K6, K7
		local V8, V9, V10, V11 = IV0, IV1, IV2, IV3
		local V12, V13, V14, V15 = Counter, N0, N1, FLAG_STREAM

		for _ = 1, 8 do
			V0 = bit32.band(V0 + V4, MASK); V12 = bit32.rrotate(bit32.bxor(V12, V0), 16)
			V8 = bit32.band(V8 + V12, MASK); V4 = bit32.rrotate(bit32.bxor(V4, V8), 12)
			V0 = bit32.band(V0 + V4, MASK); V12 = bit32.rrotate(bit32.bxor(V12, V0), 8)
			V8 = bit32.band(V8 + V12, MASK); V4 = bit32.rrotate(bit32.bxor(V4, V8), 7)

			V1 = bit32.band(V1 + V5, MASK); V13 = bit32.rrotate(bit32.bxor(V13, V1), 16)
			V9 = bit32.band(V9 + V13, MASK); V5 = bit32.rrotate(bit32.bxor(V5, V9), 12)
			V1 = bit32.band(V1 + V5, MASK); V13 = bit32.rrotate(bit32.bxor(V13, V1), 8)
			V9 = bit32.band(V9 + V13, MASK); V5 = bit32.rrotate(bit32.bxor(V5, V9), 7)

			V2 = bit32.band(V2 + V6, MASK); V14 = bit32.rrotate(bit32.bxor(V14, V2), 16)
			V10 = bit32.band(V10 + V14, MASK); V6 = bit32.rrotate(bit32.bxor(V6, V10), 12)
			V2 = bit32.band(V2 + V6, MASK); V14 = bit32.rrotate(bit32.bxor(V14, V2), 8)
			V10 = bit32.band(V10 + V14, MASK); V6 = bit32.rrotate(bit32.bxor(V6, V10), 7)

			V3 = bit32.band(V3 + V7, MASK); V15 = bit32.rrotate(bit32.bxor(V15, V3), 16)
			V11 = bit32.band(V11 + V15, MASK); V7 = bit32.rrotate(bit32.bxor(V7, V11), 12)
			V3 = bit32.band(V3 + V7, MASK); V15 = bit32.rrotate(bit32.bxor(V15, V3), 8)
			V11 = bit32.band(V11 + V15, MASK); V7 = bit32.rrotate(bit32.bxor(V7, V11), 7)

			V0 = bit32.band(V0 + V5, MASK); V15 = bit32.rrotate(bit32.bxor(V15, V0), 16)
			V10 = bit32.band(V10 + V15, MASK); V5 = bit32.rrotate(bit32.bxor(V5, V10), 12)
			V0 = bit32.band(V0 + V5, MASK); V15 = bit32.rrotate(bit32.bxor(V15, V0), 8)
			V10 = bit32.band(V10 + V15, MASK); V5 = bit32.rrotate(bit32.bxor(V5, V10), 7)

			V1 = bit32.band(V1 + V6, MASK); V12 = bit32.rrotate(bit32.bxor(V12, V1), 16)
			V11 = bit32.band(V11 + V12, MASK); V6 = bit32.rrotate(bit32.bxor(V6, V11), 12)
			V1 = bit32.band(V1 + V6, MASK); V12 = bit32.rrotate(bit32.bxor(V12, V1), 8)
			V11 = bit32.band(V11 + V12, MASK); V6 = bit32.rrotate(bit32.bxor(V6, V11), 7)

			V2 = bit32.band(V2 + V7, MASK); V13 = bit32.rrotate(bit32.bxor(V13, V2), 16)
			V8 = bit32.band(V8 + V13, MASK); V7 = bit32.rrotate(bit32.bxor(V7, V8), 12)
			V2 = bit32.band(V2 + V7, MASK); V13 = bit32.rrotate(bit32.bxor(V13, V2), 8)
			V8 = bit32.band(V8 + V13, MASK); V7 = bit32.rrotate(bit32.bxor(V7, V8), 7)

			V3 = bit32.band(V3 + V4, MASK); V14 = bit32.rrotate(bit32.bxor(V14, V3), 16)
			V9 = bit32.band(V9 + V14, MASK); V4 = bit32.rrotate(bit32.bxor(V4, V9), 12)
			V3 = bit32.band(V3 + V4, MASK); V14 = bit32.rrotate(bit32.bxor(V14, V3), 8)
			V9 = bit32.band(V9 + V14, MASK); V4 = bit32.rrotate(bit32.bxor(V4, V9), 7)
		end

		buffer.writeu32(KeystreamBuffer, 0, bit32.band(V0 + K0, MASK))
		buffer.writeu32(KeystreamBuffer, 4, bit32.band(V1 + K1, MASK))
		buffer.writeu32(KeystreamBuffer, 8, bit32.band(V2 + K2, MASK))
		buffer.writeu32(KeystreamBuffer, 12, bit32.band(V3 + K3, MASK))
		buffer.writeu32(KeystreamBuffer, 16, bit32.band(V4 + K4, MASK))
		buffer.writeu32(KeystreamBuffer, 20, bit32.band(V5 + K5, MASK))
		buffer.writeu32(KeystreamBuffer, 24, bit32.band(V6 + K6, MASK))
		buffer.writeu32(KeystreamBuffer, 28, bit32.band(V7 + K7, MASK))
		buffer.writeu32(KeystreamBuffer, 32, bit32.band(V8 + IV0, MASK))
		buffer.writeu32(KeystreamBuffer, 36, bit32.band(V9 + IV1, MASK))
		buffer.writeu32(KeystreamBuffer, 40, bit32.band(V10 + IV2, MASK))
		buffer.writeu32(KeystreamBuffer, 44, bit32.band(V11 + IV3, MASK))
		buffer.writeu32(KeystreamBuffer, 48, bit32.band(V12 + Counter, MASK))
		buffer.writeu32(KeystreamBuffer, 52, bit32.band(V13 + N0, MASK))
		buffer.writeu32(KeystreamBuffer, 56, bit32.band(V14 + N1, MASK))
		buffer.writeu32(KeystreamBuffer, 60, bit32.band(V15 + FLAG_STREAM, MASK))

		local Off = FullBlocks * 64
		local FullWords = Remaining // 4
		for I = 0, FullWords - 1 do
			buffer.writeu32(Ciphertext, Off + I * 4, bit32.bxor(
				buffer.readu32(Message, Off + I * 4),
				buffer.readu32(KeystreamBuffer, I * 4)
				))
		end

		for I = FullWords * 4, Remaining - 1 do
			buffer.writeu8(Ciphertext, Off + I, bit32.bxor(
				buffer.readu8(Message, Off + I),
				buffer.readu8(KeystreamBuffer, I)
				))
		end
	end

	local AuthData = ConstructAuthData(AAD, Commitment, Ciphertext)
	local Tag = Poly1305(AuthData, AuthKeyCopy)

	return Ciphertext, Commitment, Tag
end

function Arcturus.Decrypt(Ciphertext: buffer, Key: buffer, Nonce: buffer, Commitment: buffer, Tag: buffer, AAD: buffer?): buffer?
	if buffer.len(Key) ~= KEY_SIZE then
		error(`Key must be exactly {KEY_SIZE} bytes`, 2)
	end
	if buffer.len(Nonce) ~= NONCE_SIZE then
		error(`Nonce must be exactly {NONCE_SIZE} bytes`, 2)
	end
	if buffer.len(Commitment) ~= COMMITMENT_SIZE then
		error(`Commitment must be exactly {COMMITMENT_SIZE} bytes`, 2)
	end
	if buffer.len(Tag) ~= TAG_SIZE then
		error(`Tag must be exactly {TAG_SIZE} bytes`, 2)
	end

	local AAD = AAD or buffer.create(0)
	local CtLen = buffer.len(Ciphertext)

	local K0, K1, K2, K3, K4, K5, K6, K7, ExpectedCommitment, AuthKey, N0, N1 = DeriveKeys(Key, Nonce)

	if not ConstantTimeCompare(Commitment, ExpectedCommitment) then
		return nil
	end

	local AuthKeyCopy = buffer.create(32)
	buffer.copy(AuthKeyCopy, 0, AuthKey, 0, 32)

	local AuthData = ConstructAuthData(AAD, Commitment, Ciphertext)
	local ExpectedTag = Poly1305(AuthData, AuthKeyCopy)

	if not ConstantTimeCompare(Tag, ExpectedTag) then
		return nil
	end

	local Plaintext = buffer.create(CtLen)
	local FullBlocks = CtLen // 64
	local KeystreamBuffer = KEYSTREAM_BUFFER

	for Block = 0, FullBlocks - 1 do
		local Counter = Block + 1
		local V0, V1, V2, V3 = K0, K1, K2, K3
		local V4, V5, V6, V7 = K4, K5, K6, K7
		local V8, V9, V10, V11 = IV0, IV1, IV2, IV3
		local V12, V13, V14, V15 = Counter, N0, N1, FLAG_STREAM

		for _ = 1, 8 do
			V0 = bit32.band(V0 + V4, MASK); V12 = bit32.rrotate(bit32.bxor(V12, V0), 16)
			V8 = bit32.band(V8 + V12, MASK); V4 = bit32.rrotate(bit32.bxor(V4, V8), 12)
			V0 = bit32.band(V0 + V4, MASK); V12 = bit32.rrotate(bit32.bxor(V12, V0), 8)
			V8 = bit32.band(V8 + V12, MASK); V4 = bit32.rrotate(bit32.bxor(V4, V8), 7)

			V1 = bit32.band(V1 + V5, MASK); V13 = bit32.rrotate(bit32.bxor(V13, V1), 16)
			V9 = bit32.band(V9 + V13, MASK); V5 = bit32.rrotate(bit32.bxor(V5, V9), 12)
			V1 = bit32.band(V1 + V5, MASK); V13 = bit32.rrotate(bit32.bxor(V13, V1), 8)
			V9 = bit32.band(V9 + V13, MASK); V5 = bit32.rrotate(bit32.bxor(V5, V9), 7)

			V2 = bit32.band(V2 + V6, MASK); V14 = bit32.rrotate(bit32.bxor(V14, V2), 16)
			V10 = bit32.band(V10 + V14, MASK); V6 = bit32.rrotate(bit32.bxor(V6, V10), 12)
			V2 = bit32.band(V2 + V6, MASK); V14 = bit32.rrotate(bit32.bxor(V14, V2), 8)
			V10 = bit32.band(V10 + V14, MASK); V6 = bit32.rrotate(bit32.bxor(V6, V10), 7)

			V3 = bit32.band(V3 + V7, MASK); V15 = bit32.rrotate(bit32.bxor(V15, V3), 16)
			V11 = bit32.band(V11 + V15, MASK); V7 = bit32.rrotate(bit32.bxor(V7, V11), 12)
			V3 = bit32.band(V3 + V7, MASK); V15 = bit32.rrotate(bit32.bxor(V15, V3), 8)
			V11 = bit32.band(V11 + V15, MASK); V7 = bit32.rrotate(bit32.bxor(V7, V11), 7)

			V0 = bit32.band(V0 + V5, MASK); V15 = bit32.rrotate(bit32.bxor(V15, V0), 16)
			V10 = bit32.band(V10 + V15, MASK); V5 = bit32.rrotate(bit32.bxor(V5, V10), 12)
			V0 = bit32.band(V0 + V5, MASK); V15 = bit32.rrotate(bit32.bxor(V15, V0), 8)
			V10 = bit32.band(V10 + V15, MASK); V5 = bit32.rrotate(bit32.bxor(V5, V10), 7)

			V1 = bit32.band(V1 + V6, MASK); V12 = bit32.rrotate(bit32.bxor(V12, V1), 16)
			V11 = bit32.band(V11 + V12, MASK); V6 = bit32.rrotate(bit32.bxor(V6, V11), 12)
			V1 = bit32.band(V1 + V6, MASK); V12 = bit32.rrotate(bit32.bxor(V12, V1), 8)
			V11 = bit32.band(V11 + V12, MASK); V6 = bit32.rrotate(bit32.bxor(V6, V11), 7)

			V2 = bit32.band(V2 + V7, MASK); V13 = bit32.rrotate(bit32.bxor(V13, V2), 16)
			V8 = bit32.band(V8 + V13, MASK); V7 = bit32.rrotate(bit32.bxor(V7, V8), 12)
			V2 = bit32.band(V2 + V7, MASK); V13 = bit32.rrotate(bit32.bxor(V13, V2), 8)
			V8 = bit32.band(V8 + V13, MASK); V7 = bit32.rrotate(bit32.bxor(V7, V8), 7)

			V3 = bit32.band(V3 + V4, MASK); V14 = bit32.rrotate(bit32.bxor(V14, V3), 16)
			V9 = bit32.band(V9 + V14, MASK); V4 = bit32.rrotate(bit32.bxor(V4, V9), 12)
			V3 = bit32.band(V3 + V4, MASK); V14 = bit32.rrotate(bit32.bxor(V14, V3), 8)
			V9 = bit32.band(V9 + V14, MASK); V4 = bit32.rrotate(bit32.bxor(V4, V9), 7)
		end

		local Off = Block * 64
		buffer.writeu32(Plaintext, Off, bit32.bxor(buffer.readu32(Ciphertext, Off), bit32.band(V0 + K0, MASK)))
		buffer.writeu32(Plaintext, Off + 4, bit32.bxor(buffer.readu32(Ciphertext, Off + 4), bit32.band(V1 + K1, MASK)))
		buffer.writeu32(Plaintext, Off + 8, bit32.bxor(buffer.readu32(Ciphertext, Off + 8), bit32.band(V2 + K2, MASK)))
		buffer.writeu32(Plaintext, Off + 12, bit32.bxor(buffer.readu32(Ciphertext, Off + 12), bit32.band(V3 + K3, MASK)))
		buffer.writeu32(Plaintext, Off + 16, bit32.bxor(buffer.readu32(Ciphertext, Off + 16), bit32.band(V4 + K4, MASK)))
		buffer.writeu32(Plaintext, Off + 20, bit32.bxor(buffer.readu32(Ciphertext, Off + 20), bit32.band(V5 + K5, MASK)))
		buffer.writeu32(Plaintext, Off + 24, bit32.bxor(buffer.readu32(Ciphertext, Off + 24), bit32.band(V6 + K6, MASK)))
		buffer.writeu32(Plaintext, Off + 28, bit32.bxor(buffer.readu32(Ciphertext, Off + 28), bit32.band(V7 + K7, MASK)))
		buffer.writeu32(Plaintext, Off + 32, bit32.bxor(buffer.readu32(Ciphertext, Off + 32), bit32.band(V8 + IV0, MASK)))
		buffer.writeu32(Plaintext, Off + 36, bit32.bxor(buffer.readu32(Ciphertext, Off + 36), bit32.band(V9 + IV1, MASK)))
		buffer.writeu32(Plaintext, Off + 40, bit32.bxor(buffer.readu32(Ciphertext, Off + 40), bit32.band(V10 + IV2, MASK)))
		buffer.writeu32(Plaintext, Off + 44, bit32.bxor(buffer.readu32(Ciphertext, Off + 44), bit32.band(V11 + IV3, MASK)))
		buffer.writeu32(Plaintext, Off + 48, bit32.bxor(buffer.readu32(Ciphertext, Off + 48), bit32.band(V12 + Counter, MASK)))
		buffer.writeu32(Plaintext, Off + 52, bit32.bxor(buffer.readu32(Ciphertext, Off + 52), bit32.band(V13 + N0, MASK)))
		buffer.writeu32(Plaintext, Off + 56, bit32.bxor(buffer.readu32(Ciphertext, Off + 56), bit32.band(V14 + N1, MASK)))
		buffer.writeu32(Plaintext, Off + 60, bit32.bxor(buffer.readu32(Ciphertext, Off + 60), bit32.band(V15 + FLAG_STREAM, MASK)))
	end

	local Remaining = CtLen - FullBlocks * 64
	if Remaining > 0 then
		local Counter = FullBlocks + 1
		local V0, V1, V2, V3 = K0, K1, K2, K3
		local V4, V5, V6, V7 = K4, K5, K6, K7
		local V8, V9, V10, V11 = IV0, IV1, IV2, IV3
		local V12, V13, V14, V15 = Counter, N0, N1, FLAG_STREAM

		for _ = 1, 8 do
			V0 = bit32.band(V0 + V4, MASK); V12 = bit32.rrotate(bit32.bxor(V12, V0), 16)
			V8 = bit32.band(V8 + V12, MASK); V4 = bit32.rrotate(bit32.bxor(V4, V8), 12)
			V0 = bit32.band(V0 + V4, MASK); V12 = bit32.rrotate(bit32.bxor(V12, V0), 8)
			V8 = bit32.band(V8 + V12, MASK); V4 = bit32.rrotate(bit32.bxor(V4, V8), 7)

			V1 = bit32.band(V1 + V5, MASK); V13 = bit32.rrotate(bit32.bxor(V13, V1), 16)
			V9 = bit32.band(V9 + V13, MASK); V5 = bit32.rrotate(bit32.bxor(V5, V9), 12)
			V1 = bit32.band(V1 + V5, MASK); V13 = bit32.rrotate(bit32.bxor(V13, V1), 8)
			V9 = bit32.band(V9 + V13, MASK); V5 = bit32.rrotate(bit32.bxor(V5, V9), 7)

			V2 = bit32.band(V2 + V6, MASK); V14 = bit32.rrotate(bit32.bxor(V14, V2), 16)
			V10 = bit32.band(V10 + V14, MASK); V6 = bit32.rrotate(bit32.bxor(V6, V10), 12)
			V2 = bit32.band(V2 + V6, MASK); V14 = bit32.rrotate(bit32.bxor(V14, V2), 8)
			V10 = bit32.band(V10 + V14, MASK); V6 = bit32.rrotate(bit32.bxor(V6, V10), 7)

			V3 = bit32.band(V3 + V7, MASK); V15 = bit32.rrotate(bit32.bxor(V15, V3), 16)
			V11 = bit32.band(V11 + V15, MASK); V7 = bit32.rrotate(bit32.bxor(V7, V11), 12)
			V3 = bit32.band(V3 + V7, MASK); V15 = bit32.rrotate(bit32.bxor(V15, V3), 8)
			V11 = bit32.band(V11 + V15, MASK); V7 = bit32.rrotate(bit32.bxor(V7, V11), 7)

			V0 = bit32.band(V0 + V5, MASK); V15 = bit32.rrotate(bit32.bxor(V15, V0), 16)
			V10 = bit32.band(V10 + V15, MASK); V5 = bit32.rrotate(bit32.bxor(V5, V10), 12)
			V0 = bit32.band(V0 + V5, MASK); V15 = bit32.rrotate(bit32.bxor(V15, V0), 8)
			V10 = bit32.band(V10 + V15, MASK); V5 = bit32.rrotate(bit32.bxor(V5, V10), 7)

			V1 = bit32.band(V1 + V6, MASK); V12 = bit32.rrotate(bit32.bxor(V12, V1), 16)
			V11 = bit32.band(V11 + V12, MASK); V6 = bit32.rrotate(bit32.bxor(V6, V11), 12)
			V1 = bit32.band(V1 + V6, MASK); V12 = bit32.rrotate(bit32.bxor(V12, V1), 8)
			V11 = bit32.band(V11 + V12, MASK); V6 = bit32.rrotate(bit32.bxor(V6, V11), 7)

			V2 = bit32.band(V2 + V7, MASK); V13 = bit32.rrotate(bit32.bxor(V13, V2), 16)
			V8 = bit32.band(V8 + V13, MASK); V7 = bit32.rrotate(bit32.bxor(V7, V8), 12)
			V2 = bit32.band(V2 + V7, MASK); V13 = bit32.rrotate(bit32.bxor(V13, V2), 8)
			V8 = bit32.band(V8 + V13, MASK); V7 = bit32.rrotate(bit32.bxor(V7, V8), 7)

			V3 = bit32.band(V3 + V4, MASK); V14 = bit32.rrotate(bit32.bxor(V14, V3), 16)
			V9 = bit32.band(V9 + V14, MASK); V4 = bit32.rrotate(bit32.bxor(V4, V9), 12)
			V3 = bit32.band(V3 + V4, MASK); V14 = bit32.rrotate(bit32.bxor(V14, V3), 8)
			V9 = bit32.band(V9 + V14, MASK); V4 = bit32.rrotate(bit32.bxor(V4, V9), 7)
		end

		buffer.writeu32(KeystreamBuffer, 0, bit32.band(V0 + K0, MASK))
		buffer.writeu32(KeystreamBuffer, 4, bit32.band(V1 + K1, MASK))
		buffer.writeu32(KeystreamBuffer, 8, bit32.band(V2 + K2, MASK))
		buffer.writeu32(KeystreamBuffer, 12, bit32.band(V3 + K3, MASK))
		buffer.writeu32(KeystreamBuffer, 16, bit32.band(V4 + K4, MASK))
		buffer.writeu32(KeystreamBuffer, 20, bit32.band(V5 + K5, MASK))
		buffer.writeu32(KeystreamBuffer, 24, bit32.band(V6 + K6, MASK))
		buffer.writeu32(KeystreamBuffer, 28, bit32.band(V7 + K7, MASK))
		buffer.writeu32(KeystreamBuffer, 32, bit32.band(V8 + IV0, MASK))
		buffer.writeu32(KeystreamBuffer, 36, bit32.band(V9 + IV1, MASK))
		buffer.writeu32(KeystreamBuffer, 40, bit32.band(V10 + IV2, MASK))
		buffer.writeu32(KeystreamBuffer, 44, bit32.band(V11 + IV3, MASK))
		buffer.writeu32(KeystreamBuffer, 48, bit32.band(V12 + Counter, MASK))
		buffer.writeu32(KeystreamBuffer, 52, bit32.band(V13 + N0, MASK))
		buffer.writeu32(KeystreamBuffer, 56, bit32.band(V14 + N1, MASK))
		buffer.writeu32(KeystreamBuffer, 60, bit32.band(V15 + FLAG_STREAM, MASK))

		local Off = FullBlocks * 64
		local FullWords = Remaining // 4
		for I = 0, FullWords - 1 do
			buffer.writeu32(Plaintext, Off + I * 4, bit32.bxor(
				buffer.readu32(Ciphertext, Off + I * 4),
				buffer.readu32(KeystreamBuffer, I * 4)
				))
		end

		for I = FullWords * 4, Remaining - 1 do
			buffer.writeu8(Plaintext, Off + I, bit32.bxor(
				buffer.readu8(Ciphertext, Off + I),
				buffer.readu8(KeystreamBuffer, I)
				))
		end
	end

	return Plaintext
end

Arcturus.KEY_SIZE = KEY_SIZE
Arcturus.NONCE_SIZE = NONCE_SIZE
Arcturus.COMMITMENT_SIZE = COMMITMENT_SIZE
Arcturus.TAG_SIZE = TAG_SIZE
Arcturus.OVERHEAD = COMMITMENT_SIZE + TAG_SIZE

return Arcturus