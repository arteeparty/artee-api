scp -i $TRAVIS_BUILD_DIR/github_deploy_key $TRAVIS_BUILD_DIR/build/artee-api-linux64 artee@api.artee.party:/home/artee
ssh -i $TRAVIS_BUILD_DIR/github_deploy_key artee@api.artee.party sudo /bin/bash /home/artee/deploy.sh
