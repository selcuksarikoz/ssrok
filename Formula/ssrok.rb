class Ssrok < Formula
  desc "Blazing fast secure reverse proxy tunnel"
  homepage "https://github.com/selcuksarikoz/ssrok"
  version "0.1.7"
  
  if OS.mac?
    if Hardware::CPU.arm?
      url "https://github.com/selcuksarikoz/ssrok/releases/download/v0.1.7/ssrok-darwin-arm64"
      sha256 "2d45c364725143011a87569fa44e84949fe386f78bbe66ea2ca59007b8efa888"
    else
      url "https://github.com/selcuksarikoz/ssrok/releases/download/v0.1.7/ssrok-darwin-amd64"
      sha256 "b0110e43928b9dd3c9fa2652cad6c12bad304c0a14d549e01a856f409ca90a64"
    end
  elsif OS.linux?
    if Hardware::CPU.arm?
      url "https://github.com/selcuksarikoz/ssrok/releases/download/v0.1.7/ssrok-linux-arm64"
      sha256 "PLACEHOLDER_SHA256_LINUX_ARM64"
    else
      url "https://github.com/selcuksarikoz/ssrok/releases/download/v0.1.7/ssrok-linux-amd64"
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
