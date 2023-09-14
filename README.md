# GuildNotes

GuildNotes is an app for sharing role-based content in a gaming community, built on the [Internet Computer](https://internetcomputer.org/) as a demonstration of the [vetKeys](https://internetcomputer.org/docs/current/developer-docs/integrations/vetkeys/) encryption feature.

vetKeys is still in development and uses a hard-coded master key, so **this app should be regarded as insecure and should not be used to store any confidential information.**

Users can be added to the app at 5 levels - Owner, Admin, Conqueror, Explorer and Player. All levels can view encrypted content specific to their own level. Owners and Admins can add new users, view any content and add or modify content for any user level. Owners can also appoint and remove Admins, delete users and appoint other Owners. User content is encrypted with a master key. The master key itself is not stored but is encrypted and stored for each individual user with the user's own identity and role.

The app features two separate frontends, an Admin Dashboard and an End User Interface. A deployed instance of the Admin Dashboard can be seen at https://rctba-eqaaa-aaaao-a2h5q-cai.icp0.io/ and the End User Interface at https://rxuqn-fyaaa-aaaao-a2h6a-cai.icp0.io/. A video demonstration can be seen at https://www.youtube.com/watch?v=bC5XSoSd0Dk.

## Instructions to deploy GuildNotes locally

1. Install the [Internet Computer SDK](https://internetcomputer.org/docs/current/developer-docs/setup/install/index.mdx).

2. Clone this repo using the links at the top of the page and navigate to the folder containing the repo.

3. Use the following commands in the Command Line:
> `dfx start --clean --background`
> `npm install`
> `dfx canister create vetkeys_api --specified-id s55qq-oqaaa-aaaaa-aaakq-cai` (This is necessary because the canister ID is hard-coded within the backend.)
> `dfx deploy`

4. Open the URL displayed for either or both of `group_sharing_frontend` and `end_user_interface`.

In the local instalment, the canister owner and the anonymous identity are both appointed as Owners the first time that the app is opened in a browser after deployment. This means that you can open the app and perform all Owner functions before logging in with an Internet Identity (instructions are shown) or after refreshing the screen.

Note that this app is still in development and some features may not work as intended, but the intention is to demonstrate a potential use case of the vetKeys feature. For a brief overview of vetKeys see [this blog post](https://internetcomputer.org/blog/features/vetkey-primer), or [see here](https://internetcomputer.org/docs/current/developer-docs/integrations/vetkeys/) for further information and links.
