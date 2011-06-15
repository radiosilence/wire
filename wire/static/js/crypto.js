// Encryption
$(function() {
    window.p = {
        iter: 100000,
        mode: "ocb2",
        ks: 256
    };
});

$(function() {
    enc_form = '<h1>Security Options</h1> \
    <p><label for="crypto-key">Crypto Key</label><br/> \
        <input type="text" name="encryption_key" id="crypto-key" /> <a href="#" id="encrypt" class="button">Encrypt</a><br/> \
        If you choose to encrypt your message, a key must be decided in person and memorised by the sender and recievers. It must be 8 or more characters long. AVOID dictionary words. \
    </p>';    
    $('article#crypto').html(enc_form);
    $('article#crypto a#encrypt').live('click', function(e) {
        e.preventDefault();
        password = $('#crypto-key').val();
        plaintext = $('#msg-content').val();
        if(password.length < 6) {
            alert('password must be at least x chars');
            return false;
        }
        $('#msg-content').val(sjcl.encrypt(password, plaintext, window.p));
        $('#msg-encryption').val('aes256');

        $('article#crypto').hide();
        $('#msg').append('<div class="encrypted_message"></div>');
        console.log($('#msg-content').val());
    });
});

// Decryption
$(function() {

    decrypt_form = '<p>It seems that messages in this thread are encrypted with AES-256. Decrypt them by entering the passphrase below:</p> \
        <p><input type="text" id="passphrase"/> <a class="button" id="decrypt-button" href="#">Decrypt</a></p>';
    window.num_enc = 0;
    $('article.message div.aes256').each(function() {
        $(this).attr('enc_content', $(this).text());
        $(this).text('');
        $(this).addClass('encrypted_message');
        window.num_enc += 1;
    });
    if(window.num_enc > 0) {
        $('#decrypt').html(decrypt_form);
        $('#decrypt-button').click(function(e) {
            e.preventDefault();
            $('article.message div.aes256').each(function() {
                $(this).text(sjcl.decrypt($('#passphrase').val(), $(this).attr('enc_content'), window.p));
                $(this).removeClass('encrypted_message');
                $('#decrypt').hide();
            });
            
        })
    }
});