/* Javascript for CertRequestXBlock. */
function CertRequestXBlock(runtime, element) {

          function reloadPage(){
               location.reload();
	       //return;
          }

          var handlerUrlCert = runtime.handlerUrl(element,'generate_user_cert_xblock');

          function request_certificate() {
                course = $('#course').val();
                student = $('#student').val();
                $.ajax({
                type: "POST",
                url: handlerUrlCert,
                data: JSON.stringify({"course": course,"student":student}),
                success: reloadPage
          });
         }




    $(function ($) {
	 
	 $('#btn_generate_cert').click(function(){request_certificate();});









    });
}
