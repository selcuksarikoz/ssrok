class Ssrok < Formula
  desc "Blazing fast secure reverse proxy tunnel"
  homepage "https://github.com/selcuksarikoz/ssrok"
  version "0.1.6"
  
  if OS.mac?
    if Hardware::CPU.arm?
      url "https://github.com/selcuksarikoz/ssrok/releases/download/v0.1.6/ssrok-darwin-arm64"
      sha256 "8c7aa17a4261e776423405d34eb3d1315de6ca855f648c6b3283ca01487458fc"
    else
      url "https://github.com/selcuksarikoz/ssrok/releases/download/v0.1.6/ssrok-darwin-amd64"
      sha256 "c345767365a2dedb6bb70573be697cf28a3cff757d2fdcf49f67a9b76399f9dc"
    end
  elsif OS.linux?
    if Hardware::CPU.arm?
      url "https://github.com/selcuksarikoz/ssrok/releases/download/v0.1.6/ssrok-linux-arm64"
      sha256 "PLACEHOLDER_SHA256_LINUX_ARM64"
    else
      url "https://github.com/selcuksarikoz/ssrok/releases/download/v0.1.6/ssrok-linux-amd64"
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
