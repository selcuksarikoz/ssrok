class Ssrok < Formula
  desc "Blazing fast secure reverse proxy tunnel"
  homepage "https://github.com/selcuksarikoz/ssrok"
  version "0.1.9"
  
  if OS.mac?
    if Hardware::CPU.arm?
      url "https://github.com/selcuksarikoz/ssrok/releases/download/v0.1.9/ssrok-darwin-arm64"
      sha256 "b8dec1a6390deffc635bc5ddc99b731fb88ef9de9c2ff987395c121f63466568"
    else
      url "https://github.com/selcuksarikoz/ssrok/releases/download/v0.1.9/ssrok-darwin-amd64"
      sha256 "d331fdb406dd41908e48ae40c5abd24725fc766637a37e0194e84e6daf519503"
    end
  elsif OS.linux?
    if Hardware::CPU.arm?
      url "https://github.com/selcuksarikoz/ssrok/releases/download/v0.1.9/ssrok-linux-arm64"
      sha256 "PLACEHOLDER_SHA256_LINUX_ARM64"
    else
      url "https://github.com/selcuksarikoz/ssrok/releases/download/v0.1.9/ssrok-linux-amd64"
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
