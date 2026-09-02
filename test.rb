# Reproducer: OpenSSL does not reject prohibited keyUsage values for ML-DSA
# certificates per RFC 9881 Section 5.
#
# https://www.rfc-editor.org/rfc/rfc9881.html#section-5
#
# ML-DSA subject public keys cannot be used to establish keys or encrypt
# data, so the keyUsage extension MUST NOT have any of the following bits
# set:
#
#   keyEncipherment
#   dataEncipherment
#   keyAgreement
#   encipherOnly
#   decipherOnly
#
# Expected: OpenSSL should reject signing a certificate that pairs an ML-DSA
# key with prohibited keyUsage values.
# Actual: OpenSSL signs it without error.

require "openssl"

key = OpenSSL::PKey.generate_key("ML-DSA-65")

subject = OpenSSL::X509::Name.new([
  ["CN", "test"],
  ["DC", "example"],
])

cert = OpenSSL::X509::Certificate.new
cert.public_key = OpenSSL::PKey.read(key.public_to_der)
cert.version = 2
cert.serial = 1
cert.not_before = Time.now
cert.not_after = Time.now + 86_400

cert.subject = subject
cert.issuer = subject

ef = OpenSSL::X509::ExtensionFactory.new(nil, cert)

# All five prohibited keyUsage values for ML-DSA per RFC 9881 Section 5,
# combined with digitalSignature (the only valid one).
extensions = {
  "basicConstraints" => "CA:FALSE",
  "keyUsage" =>
    "digitalSignature,keyEncipherment,dataEncipherment,keyAgreement,encipherOnly,decipherOnly",
  "subjectKeyIdentifier" => "hash",
}

cert.extensions = extensions.map do |ext_name, value|
  ef.create_extension(ext_name, value)
end

cert.sign(key, nil)

puts "OpenSSL version: #{OpenSSL::OPENSSL_VERSION}"
puts "Ruby OpenSSL version: #{OpenSSL::VERSION}"
puts

key_usage = cert.extensions.find { |ext| ext.oid == "keyUsage" }
puts "keyUsage: #{key_usage.value}"
puts

puts "Certificate was signed successfully with prohibited keyUsage values."
puts "OpenSSL should have rejected this per RFC 9881 Section 5."
