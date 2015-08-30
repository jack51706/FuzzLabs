$( document ).ready(function() {

    var selection_start = -1;
    var selection_end = -1;

    var dHeight = $(document).height();
    $("div#parser_center_wrapper").height(dHeight - 350);

    // ------------------------------------------------------------------------
    //
    // ------------------------------------------------------------------------

    function getPrimitiveItem(type, color) {
        var pItem = document.createElement('div');
        $(pItem).css("background-color", color);
        $(pItem).css("color", "#FFFFFF");
        $(pItem).attr("type", type);
    }

    // ------------------------------------------------------------------------
    //
    // ------------------------------------------------------------------------

    function setSelection(type, color, area) {
        var hexview = document.getElementById('parser_center_wrapper');
        cNodes = hexview.childNodes;
        for (var cnc = area.start; cnc <= area.end; cnc++) {
            $(cNodes[cnc]).css("background-color", color);
            $(cNodes[cnc]).css("color", "#FFFFFF");
            $(cNodes[cnc]).attr("type", type);
            // TODO: instead of marking, the selection should be merged 
            //       according to _type_.
        }
    }

    // ------------------------------------------------------------------------
    //
    // ------------------------------------------------------------------------

    function getSelection() {
        var start = -1;
        var stop = -1;
        var hexview = document.getElementById('parser_center_wrapper');
        cNodes = hexview.childNodes;
        for (var cnc = 0; cnc < cNodes.length; cnc++) {
            if (start == -1 && $(cNodes[cnc]).hasClass("parser_hex_cell_select") == true) {
                start = cnc;
            }
            if (start != -1 && $(cNodes[cnc]).hasClass("parser_hex_cell_select") == false) {
                stop = cnc - 1;
                break;
            }
        }
        return({"start": start, "end": stop});
    }

    // ------------------------------------------------------------------------
    //
    // ------------------------------------------------------------------------

    function setAllHex() {
        var hexview = document.getElementById('parser_center_wrapper');
        cNodes = hexview.childNodes;
        for (var cnc = 0; cnc < cNodes.length; cnc++) {
            toHex(cNodes[cnc]);
        }
    }

    // ------------------------------------------------------------------------
    //
    // ------------------------------------------------------------------------

    function clearStringMarkings() {
        var hexview = document.getElementById('parser_center_wrapper');
        cNodes = hexview.childNodes;
        for (var cnc = 0; cnc < cNodes.length; cnc++) {
            $(cNodes[cnc]).removeClass("parser_hex_cell_ascii");
        }
    }

    // ------------------------------------------------------------------------
    //
    // ------------------------------------------------------------------------

    function analyzeOffsetForString(cnodes, item) {
        strlen = parseInt($("input#pa_str_min_len").val());
        cno = parseInt(item.getAttribute('offset'));
        var string = 0;

        var cc = 0;
        var char = cnodes[cno + cc].getAttribute('raw').charCodeAt(0);
        while (char >= 32 && char <= 126) {
            cc++;
            char = cnodes[cno + cc].getAttribute('raw').charCodeAt(0);
        }

        if (cc < strlen) return 0;

        cc = 0;
        var char = cnodes[cno].getAttribute('raw').charCodeAt(0);
        while (char >= 32 && char <= 126) {
            toAscii(cnodes[cno + cc]);
            cc++;
            char = cnodes[cno + cc].getAttribute('raw').charCodeAt(0);
        }
        return cc;
    }

    // ------------------------------------------------------------------------
    //
    // ------------------------------------------------------------------------

    function findStrings() {
        clearStringMarkings();
        var hexview = document.getElementById('parser_center_wrapper');
        cNodes = hexview.childNodes;

        for (var cnc = 0; cnc < cNodes.length; cnc++) {
            cnc += analyzeOffsetForString(cNodes, cNodes[cnc]);
        }

    }

    // ------------------------------------------------------------------------
    //
    // ------------------------------------------------------------------------

    $(function(){
        $('#the-node').contextMenu({
            selector: 'div.parser_hex_cell', 
            callback: function(key, options) {
                if (key == "ascii") toAscii($(this));
                if (key == "hex") toHex($(this));
            },
            items: {
                "hex": {name: "To Hex"},
                "ascii": {name: "To Ascii"}
            }
        });
    });

    // ------------------------------------------------------------------------
    //
    // ------------------------------------------------------------------------

    function toAscii(item) {
        $(item).removeClass('parser_hex_cell_ascii');
        var raw = $(item).attr('raw');
        $(item).text(raw);
        $(item).addClass('parser_hex_cell_ascii');
    }

    // ------------------------------------------------------------------------
    //
    // ------------------------------------------------------------------------

    function toHex(item) {
        $(item).removeClass('parser_hex_cell_ascii');
        var raw = $(item).attr('raw');
        $(item).text(fixHex(parseInt(raw.charCodeAt(0)).toString(16)).toUpperCase());
    }

    // ------------------------------------------------------------------------
    //
    // ------------------------------------------------------------------------

    function fixHex(val) {
        if (val.length % 2) return ("0" + val);
        return val;
    }

    // ------------------------------------------------------------------------
    //
    // ------------------------------------------------------------------------

    function selectBytes(from, to) {
        var hexview = document.getElementById('parser_center_wrapper');
        cNodes = hexview.childNodes;
        for (var cnc = 0; cnc < cNodes.length; cnc++) {
            cno = parseInt(cNodes[cnc].getAttribute('offset'));
            if (cno >= from && cno <= to) {
                $(cNodes[cnc]).addClass("parser_hex_cell_select");
            }
        }
    }

    // ------------------------------------------------------------------------
    //
    // ------------------------------------------------------------------------

    function clearAllSelection() {
        selection_start = -1;
        selection_end = -1;
        var hexview = document.getElementById('parser_center_wrapper');
        cNodes = hexview.childNodes;
        for (var cnc = 0; cnc < cNodes.length; cnc++) {
            $(cNodes[cnc]).removeClass("parser_hex_cell_select");
        }
    }

    // ------------------------------------------------------------------------
    //
    // ------------------------------------------------------------------------

    function hexViewByte(val, offset, all_hex) {
        var item = document.createElement('div');
        item.setAttribute('class', 'unselectable parser_hex_cell');
        item.setAttribute('raw', val);
        item.setAttribute('dec', val.charCodeAt(0));
        item.setAttribute('hex', fixHex(val));
        item.setAttribute('offset', parseInt(offset));

        item.setAttribute('class', 'unselectable parser_hex_cell');
        val = val.charCodeAt(0).toString(16);
        item.setAttribute('value', fixHex(val));
        item.textContent = fixHex(val).toUpperCase();
        return item;
    }

    // ------------------------------------------------------------------------
    //
    // ------------------------------------------------------------------------

    function processFile(all_hex) {
        var hexview = document.getElementById('parser_center_wrapper');
        var file_data = window.localStorage.getItem('parser_file_content');
        hexview.innerHTML = "";
        var bcnt = 0;

        for (bcnt = 0; bcnt < file_data.length; bcnt++) {
            var hvItem = hexViewByte(file_data[bcnt], bcnt, all_hex);
            hexview.appendChild(hvItem);
        }

        findStrings();
    }

    // ------------------------------------------------------------------------
    //
    // ------------------------------------------------------------------------

    $("body").on('mouseover', 'div.parser_hex_cell', function(evt) {
        $(evt.target).addClass("parser_hex_cell_mark");
        var offset_info = $("div#offset_info").get(0);
        var byte_info_hex = $("div#byte_info_hex").get(0);
        var byte_info_dec = $("div#byte_info_dec").get(0);
        var byte_info_raw = $("div#byte_info_raw").get(0);
        var raw = evt.target.getAttribute('raw');
        var offset = evt.target.getAttribute('offset');
        var offset_info = document.getElementById('offset_info');
        byte_info_raw.textContent = "Raw: " + raw;
        byte_info_dec.textContent = "Dec: " + raw.charCodeAt(0);
        byte_info_hex.textContent = "Hex: " + fixHex(raw.charCodeAt(0).toString(16)).toUpperCase();
        offset_info.textContent = "Offset: " + offset + 
                                  " (0x" + 
                                  fixHex(parseInt(offset).toString(16)).toUpperCase() + 
                                  ")";
    });

    // ------------------------------------------------------------------------
    //
    // ------------------------------------------------------------------------

    $("body").on('mouseout', 'div.parser_hex_cell', function(evt) {
        $(evt.target).removeClass("parser_hex_cell_mark");
    });

    // ------------------------------------------------------------------------
    //
    // ------------------------------------------------------------------------

    $("body").on('mousedown', 'div.parser_hex_cell', function(evt) {
        /*
            1 = Left   mouse button
            2 = Centre mouse button
            3 = Right  mouse button
        */
        clearAllSelection();
        if (evt.which === 1) {
            selection_start = parseInt($(evt.target).attr('offset'));
        }
    });

    // ------------------------------------------------------------------------
    //
    // ------------------------------------------------------------------------

    $("button.parser_reset").click(function () {
        processFile(false);
    });

    // ------------------------------------------------------------------------
    //
    // ------------------------------------------------------------------------

    $("button.primitive_type").click(function () {
        var p_type = $(this).attr('id').split("_")[1];
        var color = $(this).css('background-color');
        setSelection(p_type, color, getSelection());
    });

    // ------------------------------------------------------------------------
    //
    // ------------------------------------------------------------------------

    $("input#pa_str_min_len").change(function() {
        setAllHex();
        findStrings();
    });

    // ------------------------------------------------------------------------
    //
    // ------------------------------------------------------------------------

    $("body").on('mouseup', 'div.parser_hex_cell', function(evt) {
        selection_end = parseInt($(evt.target).attr('offset'));
        selectBytes(selection_start, selection_end);
    });

    // ------------------------------------------------------------------------
    //
    // ------------------------------------------------------------------------

    $("#parser_source_file").change(function() {
        var file = this.files[0];
        var reader = new FileReader();

        reader.onload = function(evt) {
            window.localStorage.setItem('parser_file', file);
            window.localStorage.setItem('parser_file_content', evt.target.result);
            processFile(false);
        };

        reader.readAsBinaryString(file);
    });

});

