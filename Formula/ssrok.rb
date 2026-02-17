class Ssrok < Formula
  desc "Blazing fast secure reverse proxy tunnel"
  homepage "https://github.com/selcuksarikoz/ssrok"
  version "0.1.8"
  
  if OS.mac?
    if Hardware::CPU.arm?
      url "https://github.com/selcuksarikoz/ssrok/releases/download/v0.1.8/ssrok-darwin-arm64"
      sha256 "908b0a5a6be1ef31e34d2293a8bfece0deb1f02f41b4d973e2ad7a6f43a4af03"
    else
      url "https://github.com/selcuksarikoz/ssrok/releases/download/v0.1.8/ssrok-darwin-amd64"
      sha256 "54c26221118d8b157e5be5b3e7d94b66283a3a14ebb8c1188889022658bde979"
    end
  elsif OS.linux?
    if Hardware::CPU.arm?
      url "https://github.com/selcuksarikoz/ssrok/releases/download/v0.1.8/ssrok-linux-arm64"
      sha256 "PLACEHOLDER_SHA256_LINUX_ARM64"
    else
      url "https://github.com/selcuksarikoz/ssrok/releases/download/v0.1.8/ssrok-linux-amd64"
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
