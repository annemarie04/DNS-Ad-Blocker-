file = 'blockedDocker.txt'

adsDict = {}
googleAds = 0
facebookAds = 0

# Read from file
with open(file, 'r') as file:
    lines = file.readlines()

# Print the lines
for line in lines:
    ad = line.strip()
    if ad in adsDict:
        adsDict[ad] += 1
    else:
        adsDict[ad] = 1
    if 'google' in ad:
        googleAds += 1
    if 'facebook' in ad:
        facebookAds += 1

# Sort the ads by the number of times they appear
sortedAds = sorted(adsDict.items(), key=lambda x: x[1], reverse=True)

# Get the top 5 ads blocked
mostBlocked = sortedAds[:5]

print("----------------- Ads Statistics ----------------- \n")
print("Top 5 ads blocked:")
# Print the top 5 ads
for ad, timesBlocked in mostBlocked:
    print(f"{ad}: {timesBlocked}")
print('\n')
# Print the number of ads blocked by platform (google, facebook)
print("Ads blocked by platform:")
print(f"Google ads: {googleAds}")
print(f"Facebook ads: {facebookAds}")

