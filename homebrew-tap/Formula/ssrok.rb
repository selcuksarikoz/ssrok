class Ssrok < Formula
  desc "Blazing fast secure reverse proxy tunnel"
  homepage "https://github.com/selcuksarikoz/ssrok"
  version "1.0.8"
  
  if OS.mac?
    if Hardware::CPU.arm?
      url "https://github.com/selcuksarikoz/ssrok/releases/download/v1.0.8/ssrok-darwin-arm64"
      sha256 "6e52fde5aebbab12b2dd1dbd71f10e34eda2a0fab08bafba543fbc905e9a58a3"
    else
      url "https://github.com/selcuksarikoz/ssrok/releases/download/v1.0.8/ssrok-darwin-amd64"
      sha256 "b90b434cd7dd91699fb407f2bb8960b7bbabba1661236d783c10df3fb5c73b91"
    end
  elsif OS.linux?
    if Hardware::CPU.arm?
      url "https://github.com/selcuksarikoz/ssrok/releases/download/v1.0.8/ssrok-linux-arm64"
      sha256 "PLACEHOLDER_SHA256_LINUX_ARM64"
    else
      url "https://github.com/selcuksarikoz/ssrok/releases/download/v1.0.8/ssrok-linux-amd64"
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
