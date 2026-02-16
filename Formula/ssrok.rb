class Ssrok < Formula
  desc "Blazing fast secure reverse proxy tunnel"
  homepage "https://github.com/selcuksarikoz/ssrok"
  version "0.1.4"
  
  if OS.mac?
    if Hardware::CPU.arm?
      url "https://github.com/selcuksarikoz/ssrok/releases/download/v0.1.4/ssrok-darwin-arm64"
      sha256 "bf05d41705ef0397e9dc78f2d934931a06aa9436cdf17ed5de870d58c9ba0c99"
    else
      url "https://github.com/selcuksarikoz/ssrok/releases/download/v0.1.4/ssrok-darwin-amd64"
      sha256 "c77eee8bf465935eb35c30cd0a09d7b28a3daeba518f01efae5c37d6ba85bf6e"
    end
  elsif OS.linux?
    if Hardware::CPU.arm?
      url "https://github.com/selcuksarikoz/ssrok/releases/download/v0.1.4/ssrok-linux-arm64"
      sha256 "PLACEHOLDER_SHA256_LINUX_ARM64"
    else
      url "https://github.com/selcuksarikoz/ssrok/releases/download/v0.1.4/ssrok-linux-amd64"
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
