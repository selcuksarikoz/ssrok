class Ssrok < Formula
  desc "Blazing fast secure reverse proxy tunnel"
  homepage "https://github.com/selcuksarikoz/ssrok"
  version "0.1.12"
  
  if OS.mac?
    if Hardware::CPU.arm?
      url "https://github.com/selcuksarikoz/ssrok/releases/download/v0.1.12/ssrok-darwin-arm64"
      sha256 "e57c6e60366ccce84604fc1bcdfd2d752c21a75cb92064a94278ce51f67e0be3"
    else
      url "https://github.com/selcuksarikoz/ssrok/releases/download/v0.1.12/ssrok-darwin-amd64"
      sha256 "3262a8a8cc6001e2f0caf1373423956d63cea04736973a4494f8ecfe7703f7e4"
    end
  elsif OS.linux?
    if Hardware::CPU.arm?
      url "https://github.com/selcuksarikoz/ssrok/releases/download/v0.1.12/ssrok-linux-arm64"
      sha256 "PLACEHOLDER_SHA256_LINUX_ARM64"
    else
      url "https://github.com/selcuksarikoz/ssrok/releases/download/v0.1.12/ssrok-linux-amd64"
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
