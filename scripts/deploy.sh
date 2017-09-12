echo $TRAVIS_BUILD_DIR
ls $TRAVIS_BUILD_DIR
scp $TRAVIS_BUILD_DIR/build/artee-api-linux64 artee@api.artee.party:/home/artee
ssh artee@api.artee.party sudo /bin/bash /home/artee/deploy.sh
