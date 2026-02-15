class Ssrok < Formula
  desc "Blazing fast secure reverse proxy tunnel"
  homepage "https://github.com/selcuksarikoz/ssrok"
  version "0.1.2"
  
  if OS.mac?
    if Hardware::CPU.arm?
      url "https://github.com/selcuksarikoz/ssrok/releases/download/v0.1.2/ssrok-darwin-arm64"
      sha256 "97f626a75fddd592f22116f2642f0732966697a8f034b4928281e5428cebe10b"
    else
      url "https://github.com/selcuksarikoz/ssrok/releases/download/v0.1.2/ssrok-darwin-amd64"
      sha256 "2ee46ce27bec82291f7fe7d1fb5f5100a9e1a15b3b3750bc54a09c150cad4bb5"
    end
  elsif OS.linux?
    if Hardware::CPU.arm?
      url "https://github.com/selcuksarikoz/ssrok/releases/download/v0.1.2/ssrok-linux-arm64"
      sha256 "PLACEHOLDER_SHA256_LINUX_ARM64"
    else
      url "https://github.com/selcuksarikoz/ssrok/releases/download/v0.1.2/ssrok-linux-amd64"
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
