class Ssrok < Formula
  desc "Blazing fast secure reverse proxy tunnel"
  homepage "https://github.com/selcuksarikoz/ssrok"
  version "0.1.10"
  
  if OS.mac?
    if Hardware::CPU.arm?
      url "https://github.com/selcuksarikoz/ssrok/releases/download/v0.1.10/ssrok-darwin-arm64"
      sha256 "87bca4139e7724b50382672b2e89980178b3a3387a15ad7818e8929d6b498172"
    else
      url "https://github.com/selcuksarikoz/ssrok/releases/download/v0.1.10/ssrok-darwin-amd64"
      sha256 "6eddd7680b1cfa8faccc5f1bf6d890c57ceda27988ae81af3b24df71a873264c"
    end
  elsif OS.linux?
    if Hardware::CPU.arm?
      url "https://github.com/selcuksarikoz/ssrok/releases/download/v0.1.10/ssrok-linux-arm64"
      sha256 "PLACEHOLDER_SHA256_LINUX_ARM64"
    else
      url "https://github.com/selcuksarikoz/ssrok/releases/download/v0.1.10/ssrok-linux-amd64"
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
