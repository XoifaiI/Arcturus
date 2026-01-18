local ReplicatedStorage = game:GetService("ReplicatedStorage")
local Cryptography = require(ReplicatedStorage.Cryptography)

local Blake3 = Cryptography.Hashing.Blake3
local ChaCha20 = Cryptography.Encryption.AEAD.ChaCha20

local ENCRYPTION_CONTEXT = string.rep("b", 32)
local AUTH_CONTEXT = string.rep("a", 32)

local KEY_SIZE = 32
local NONCE_SIZE = 32
local TAG_SIZE = 32

local function ConcatBuffers(...)
	local Parts = {...}
	local TotalLen = 0

	for _, Part in ipairs(Parts) do
		TotalLen += buffer.len(Part)
	end

	local Result = buffer.create(TotalLen)
	local Offset = 0

	for _, Part in ipairs(Parts) do
		buffer.copy(Result, Offset, Part)
		Offset += buffer.len(Part)
	end

	return Result
end

local function ConstantTimeCompare(Buffer1: buffer, Buffer2: buffer): boolean
	local Length1 = buffer.len(Buffer1)
	local Length2 = buffer.len(Buffer2)
	if Length1 ~= Length2 then
		return false
	end

	local Difference = 0
	for Index = 0, Length1 - 1 do
		Difference = bit32.bor(Difference, bit32.bxor(
			buffer.readu8(Buffer1, Index),
			buffer.readu8(Buffer2, Index)
			))
	end

	return Difference == 0
end

local function NumberToLeBytes(Num: number): buffer
	local Result = buffer.create(8)
	for I = 0, 7 do
		buffer.writeu8(Result, I, math.floor(Num / (2 ^ (I * 8))) % 256)
	end

	return Result
end

local Custom = {}
Custom.__index = Custom

function Custom.New(Key: buffer)
	assert(buffer.len(Key) == KEY_SIZE, "Key must be 32 bytes")

	local self = setmetatable({}, Custom)
	self.Key = Key
	self.AuthenticationKey = select(2, Blake3.DigestKeyed(buffer.fromstring(AUTH_CONTEXT), Key, 32))

	return self
end

function Custom:EncryptDetached(Nonce: buffer, Plaintext: buffer, Aad: buffer): buffer
	assert(buffer.len(Nonce) == NONCE_SIZE, "Nonce must be 32 bytes")

	local KeyMaterial = ConcatBuffers(self.Key, Nonce)
	local _, EncryptionKey = Blake3.DigestKeyed(buffer.fromstring(ENCRYPTION_CONTEXT), KeyMaterial, 32)

	local ChachaNonce = buffer.create(12)
	buffer.copy(ChachaNonce, 0, Nonce, 0, 8)

	local Ciphertext = ChaCha20(Plaintext, EncryptionKey, ChachaNonce, 0, 12)

	local AadLen = NumberToLeBytes(buffer.len(Aad))
	local CiphertextLen = NumberToLeBytes(buffer.len(Ciphertext))

	local MacInput = ConcatBuffers(Nonce, Aad, AadLen, Ciphertext, CiphertextLen)
	local _, Tag = Blake3.DigestKeyed(self.AuthenticationKey, MacInput, 32)

	buffer.copy(Plaintext, 0, Ciphertext)

	return Tag
end

function Custom:DecryptDetached(Nonce: buffer, Ciphertext: buffer, Tag: buffer, Aad: buffer): boolean
	assert(buffer.len(Nonce) == NONCE_SIZE, "Nonce must be 32 bytes")
	assert(buffer.len(Tag) == TAG_SIZE, "Tag must be 32 bytes")

	local AadLen = NumberToLeBytes(buffer.len(Aad))
	local CiphertextLen = NumberToLeBytes(buffer.len(Ciphertext))

	local MacInput = ConcatBuffers(Nonce, Aad, AadLen, Ciphertext, CiphertextLen)
	local _, ExpectedTag = Blake3.DigestKeyed(self.AuthenticationKey, MacInput, 32)

	if not ConstantTimeCompare(ExpectedTag, Tag) then
		return false
	end

	local KeyMaterial = ConcatBuffers(self.Key, Nonce)
	local _, EncryptionKey = Blake3.DigestKeyed(buffer.fromstring(ENCRYPTION_CONTEXT), KeyMaterial, 32)

	local ChachaNonce = buffer.create(12)
	buffer.copy(ChachaNonce, 0, Nonce, 0, 8)

	local Plaintext = ChaCha20(Ciphertext, EncryptionKey, ChachaNonce, 0, 12)

	buffer.copy(Ciphertext, 0, Plaintext)

	return true
end

function Custom.Encrypt(self, Nonce: buffer, Plaintext: buffer, Aad: buffer): buffer
	local PlaintextCopy = buffer.create(buffer.len(Plaintext))
	buffer.copy(PlaintextCopy, 0, Plaintext)

	local Tag = self:EncryptDetached(Nonce, PlaintextCopy, Aad)

	local Result = buffer.create(buffer.len(PlaintextCopy) + buffer.len(Tag))
	buffer.copy(Result, 0, PlaintextCopy)
	buffer.copy(Result, buffer.len(PlaintextCopy), Tag)

	return Result
end

function Custom.Decrypt(self, Nonce: buffer, Ciphertext: buffer, Aad: buffer): buffer?
	if buffer.len(Ciphertext) < TAG_SIZE then
		return nil
	end

	local PlaintextLen = buffer.len(Ciphertext) - TAG_SIZE
	local PlaintextPart = buffer.create(PlaintextLen)
	local TagPart = buffer.create(TAG_SIZE)

	buffer.copy(PlaintextPart, 0, Ciphertext, 0, PlaintextLen)
	buffer.copy(TagPart, 0, Ciphertext, PlaintextLen, TAG_SIZE)

	local Success = self:DecryptDetached(Nonce, PlaintextPart, TagPart, Aad)

	if Success then
		return PlaintextPart
	else
		return nil
	end
end

return Custom
