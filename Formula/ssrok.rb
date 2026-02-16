class Ssrok < Formula
  desc "Blazing fast secure reverse proxy tunnel"
  homepage "https://github.com/selcuksarikoz/ssrok"
  version "0.1.5"
  
  if OS.mac?
    if Hardware::CPU.arm?
      url "https://github.com/selcuksarikoz/ssrok/releases/download/v0.1.5/ssrok-darwin-arm64"
      sha256 "a9da5b9a8e6b32493c1c169ac3469706938307663ad7c35413d5673a9fd36112"
    else
      url "https://github.com/selcuksarikoz/ssrok/releases/download/v0.1.5/ssrok-darwin-amd64"
      sha256 "a02088a2c698a1984be3d628f636be54fa81008c35209ea8a47bdfe221ccbcb6"
    end
  elsif OS.linux?
    if Hardware::CPU.arm?
      url "https://github.com/selcuksarikoz/ssrok/releases/download/v0.1.5/ssrok-linux-arm64"
      sha256 "PLACEHOLDER_SHA256_LINUX_ARM64"
    else
      url "https://github.com/selcuksarikoz/ssrok/releases/download/v0.1.5/ssrok-linux-amd64"
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
