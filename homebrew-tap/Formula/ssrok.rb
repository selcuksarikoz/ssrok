class Ssrok < Formula
  desc "Blazing fast secure reverse proxy tunnel"
  homepage "https://github.com/ssrok/ssrok"
  version "1.0.6"
  
  if OS.mac?
    if Hardware::CPU.arm?
      url "https://github.com/ssrok/ssrok/releases/download/v1.0.0/ssrok-darwin-arm64"
      sha256 "97d9f4397ad9a0f8a594feb50d25c76aa067d2db1ba77e5342f2ab4e2d350d08"
    else
      url "https://github.com/ssrok/ssrok/releases/download/v1.0.0/ssrok-darwin-amd64"
      sha256 "82b738ddd1cb87883a16fcb53096bc4494648c5a5b77b42846e3d577b75d54a4"
    end
  elsif OS.linux?
    if Hardware::CPU.arm?
      url "https://github.com/ssrok/ssrok/releases/download/v1.0.0/ssrok-linux-arm64"
      sha256 "PLACEHOLDER_SHA256_LINUX_ARM64"
    else
      url "https://github.com/ssrok/ssrok/releases/download/v1.0.0/ssrok-linux-amd64"
      sha256 "PLACEHOLDER_SHA256_LINUX_AMD64"
    end
  end

  def install
    bin.install Dir["*"].first => "ssrok"
  end

  test do
    system "#{bin}/ssrok", "--help"
  end
end
