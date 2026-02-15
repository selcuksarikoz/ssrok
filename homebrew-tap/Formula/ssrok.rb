class Ssrok < Formula
  desc "Blazing fast secure reverse proxy tunnel"
  homepage "https://github.com/selcuksarikoz/ssrok"
  version "1.0.9"
  
  if OS.mac?
    if Hardware::CPU.arm?
      url "https://github.com/selcuksarikoz/ssrok/releases/download/v1.0.9/ssrok-darwin-arm64"
      sha256 "7d95639c081d559046c4ca79212443e2c572e944929b546d909715c3cbf4fec1"
    else
      url "https://github.com/selcuksarikoz/ssrok/releases/download/v1.0.9/ssrok-darwin-amd64"
      sha256 "1b390b716b5462fd2ae106ad781ce40e903e63c62203215bc64d5b1f577ae91c"
    end
  elsif OS.linux?
    if Hardware::CPU.arm?
      url "https://github.com/selcuksarikoz/ssrok/releases/download/v1.0.9/ssrok-linux-arm64"
      sha256 "PLACEHOLDER_SHA256_LINUX_ARM64"
    else
      url "https://github.com/selcuksarikoz/ssrok/releases/download/v1.0.9/ssrok-linux-amd64"
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
