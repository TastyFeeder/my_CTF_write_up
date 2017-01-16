<?php
if (! $FROM_INCLUDE)
    exit('not allow direct access');

function RandomString()
{
    $characters = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    $randstring = "";
    for ($i = 0; $i < 9; $i++) {
        $randstring .= $characters[rand(0, strlen($characters)-1)];
    }
    return $randstring;
}

$target_dir = "images/";
$target_file = $target_dir . basename($_FILES["fileToUpload"]["name"]);
$uploadOk = 0;
$imageFileType = pathinfo($target_file, PATHINFO_EXTENSION);
$fsize = $_FILES['fileToUpload']['size'];
$newid = RandomString();
$newname = $newid . ".jpg";

if(isset($_FILES["fileToUpload"])) {
    if($imageFileType == "jpg")
    {
        $uploadOk = 1;
    }
    else
    {
        echo "<center><p>Sorry,we only accept jpg file</p></center>";
        $uploadOk = 0;
    }

    if(!($fsize >= 0 && $fsize <= 200000))
    {
        $uploadOk = 0;
        echo "<center><p>Sorry, the size too large.</p></center>";
    }
}

if($uploadOk)
{
    $newpath = $target_dir . $newname;

    if (move_uploaded_file($_FILES["fileToUpload"]["tmp_name"], $newpath))
    {
        header('Location: ./images/' . $newid.'.jpg');
        exit();
    }
    else
    {
        echo "<center><p>Sorry, there was an error in uploading your file.</p></center>";
    }
}
?>

<!-- Page Content -->
<div class="container">
    <!-- Marketing Icons Section -->
    <div class="row">
        <form method="POST" enctype="multipart/form-data">
            <div class="form-group">
                <label class="control-label">Select a good Snoopy picture (JPG only)</label>
                <input id="input-1" name="fileToUpload" type="file" class="file">
            </div>
        </form>
    </div>
    <script>
    // initialize with defaults
    $("#input-1").fileinput();

    // with plugin options
    $("#input-1").fileinput({'showUpload':false, 'previewFileType':'any'});
    </script>
</div>
