class Ssrok < Formula
  desc "Blazing fast secure reverse proxy tunnel"
  homepage "https://github.com/ssrok/ssrok"
  version "1.0.0"
  
  if OS.mac?
    if Hardware::CPU.arm?
      url "https://github.com/ssrok/ssrok/releases/download/v1.0.0/ssrok-darwin-arm64"
      sha256 "PLACEHOLDER_SHA256_DARWIN_ARM64"
    else
      url "https://github.com/ssrok/ssrok/releases/download/v1.0.0/ssrok-darwin-amd64"
      sha256 "PLACEHOLDER_SHA256_DARWIN_AMD64"
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
