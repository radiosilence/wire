$(function(){   
    var uploader2 = new qq.FileUploader({
        element: $('#avafile-uploader')[0],
        action: 'put/save_image',
        onComplete: function(id, fileName, responseJSON){
          var fn = responseJSON['filename']+'.'+responseJSON['ext'];
          $('#avafile_img').attr('src','img/avatar/'+fn);
          $('#avafile_img').css('display','block');
          $('#avafile').val(fn);
        },
        params: {
          _tok: $.cookie('tok'),
          type: "avatar"
        }
    });
});    