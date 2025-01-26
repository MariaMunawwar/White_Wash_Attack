
const bcrypt = require('bcryptjs');
const password = 'maheen'; // The password to test
const hash = '$2a$12$696yAXWumVRYYYQoGN1xeuKfR5LBdxz3RxjJmsnsqBEnLC.diNK56'; // The hash from your database

bcrypt.compare(password, hash, function(err, result) {
  if (err) {
    console.error('Error comparing password and hash:', err);
    return;
  }
  console.log('Do the password and hash match?', result);
});


/*
const bcrypt = require('bcryptjs');
const password = 'maheen';
bcrypt.genSalt(12, (err, salt) => {
    bcrypt.hash(password, salt, (err, hash) => {
        console.log(`New hash: ${hash}`);
        // Use the new hash in your bcrypt-test.js script to compare
    });
});
*/