class Ssrok < Formula
  desc "Blazing fast secure reverse proxy tunnel"
  homepage "https://github.com/selcuksarikoz/ssrok"
  version "1.0.10"
  
  if OS.mac?
    if Hardware::CPU.arm?
      url "https://github.com/selcuksarikoz/ssrok/releases/download/v1.0.10/ssrok-darwin-arm64"
      sha256 "7e30e0f597244514e8a683568d5953eb28032462f47d719e6fc5697289b3baed"
    else
      url "https://github.com/selcuksarikoz/ssrok/releases/download/v1.0.10/ssrok-darwin-amd64"
      sha256 "ca3889e02b4097b05ddf85f4ca1a3be84c37a76e3c26a7f13234b61e5ac8b1ff"
    end
  elsif OS.linux?
    if Hardware::CPU.arm?
      url "https://github.com/selcuksarikoz/ssrok/releases/download/v1.0.10/ssrok-linux-arm64"
      sha256 "PLACEHOLDER_SHA256_LINUX_ARM64"
    else
      url "https://github.com/selcuksarikoz/ssrok/releases/download/v1.0.10/ssrok-linux-amd64"
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
