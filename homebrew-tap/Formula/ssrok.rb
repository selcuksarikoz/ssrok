class Ssrok < Formula
  desc "Blazing fast secure reverse proxy tunnel"
  homepage "https://github.com/selcuksarikoz/ssrok"
  version "0.1.1"
  
  if OS.mac?
    if Hardware::CPU.arm?
      url "https://github.com/selcuksarikoz/ssrok/releases/download/v0.1.1/ssrok-darwin-arm64"
      sha256 "becdfe2e889713e084a253bc2c9d79beccf98b5fbde0ad97021c1e8bad79cf7f"
    else
      url "https://github.com/selcuksarikoz/ssrok/releases/download/v0.1.1/ssrok-darwin-amd64"
      sha256 "6dcc63a4b0932019711bf22a676cd4d1f163d1ff0fc4102f1ba217e5e8ed59e9"
    end
  elsif OS.linux?
    if Hardware::CPU.arm?
      url "https://github.com/selcuksarikoz/ssrok/releases/download/v0.1.1/ssrok-linux-arm64"
      sha256 "PLACEHOLDER_SHA256_LINUX_ARM64"
    else
      url "https://github.com/selcuksarikoz/ssrok/releases/download/v0.1.1/ssrok-linux-amd64"
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
