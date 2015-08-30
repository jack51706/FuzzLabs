$( document ).ready(function() {

    var selection_start = -1;
    var selection_end = -1;

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

    $("button.parser_reset").click(function () { 
        process_file(false);
    });

    $("button.primitive_type").click(function () { 
        var p_type = $(this).attr('id').split("_")[1];
        var color = $(this).css('background-color');
        setSelection(p_type, color, getSelection());
    });

    function setSelection(type, color, area) {
        var hexview = document.getElementById('parser_center_wrapper');
        cNodes = hexview.childNodes;
        for (var cnc = area.start; cnc <= area.end; cnc++) {
            $(cNodes[cnc]).css("background-color", color);
            $(cNodes[cnc]).css("color", "#FFFFFF");
        }
    }

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

    function set_all_hex() {
        var hexview = document.getElementById('parser_center_wrapper');
        cNodes = hexview.childNodes;
        for (var cnc = 0; cnc < cNodes.length; cnc++) {
            var coff = $(cNodes[cnc]).attr("offset");
            to_hex(cNodes[cnc], coff);
        }
    }

    function clear_string_markings() {
        var hexview = document.getElementById('parser_center_wrapper');
        cNodes = hexview.childNodes;
        for (var cnc = 0; cnc < cNodes.length; cnc++) {
            $(cNodes[cnc]).removeClass("parser_hex_cell_ascii");
        }
    }

    function analyse_offset_for_string(cnodes, item) {
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
            to_ascii(cnodes[cno + cc], cno + cc);
            cc++;
            char = cnodes[cno + cc].getAttribute('raw').charCodeAt(0);
        }
        return cc;
    }

    function find_strings() {
        clear_string_markings();
        var hexview = document.getElementById('parser_center_wrapper');
        cNodes = hexview.childNodes;

        for (var cnc = 0; cnc < cNodes.length; cnc++) {
            cnc += analyse_offset_for_string(cNodes, cNodes[cnc]);
        }

    }

    $("input#pa_str_min_len").change(function() {
        set_all_hex();
        find_strings();
    });

    $("body").on('mouseup', 'div.parser_hex_cell', function(evt) {
        selection_end = parseInt($(evt.target).attr('offset'));
        selectBytes(selection_start, selection_end);
    });

    $(function(){
        $('#the-node').contextMenu({
            selector: 'div.parser_hex_cell', 
            callback: function(key, options) {
                if (key == "ascii") to_ascii($(this), parseInt($(this).attr('offset')));
                if (key == "hex") to_hex($(this), parseInt($(this).attr('offset')));
            },
            items: {
                "hex": {name: "To Hex"},
                "ascii": {name: "To Ascii"}
            }
        });
    });

    var dHeight = $(document).height();
    $("div#parser_center_wrapper").height(dHeight - 250);

    function to_ascii(item, offset) {
        $(item).removeClass('parser_hex_cell_ascii');
        var raw = $(item).attr('raw');
        $(item).text(raw);
        $(item).addClass('parser_hex_cell_ascii');
    }

    function to_hex(item, offset) {
        $(item).removeClass('parser_hex_cell_ascii');
        var raw = $(item).attr('raw');
        $(item).text(fixHex(parseInt(raw.charCodeAt(0)).toString(16)).toUpperCase());
    }

    function fixHex(val) {
        if (val.length % 2) return ("0" + val);
        return val;
    }

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

    function clearSelection(item) {
        $(item).removeClass("parser_hex_cell_select");
    }

    function clearLastSelection() {
        var hexview = document.getElementById('parser_center_wrapper');
        cNodes = hexview.childNodes;
        for (var cnc = 0; cnc < cNodes.length; cnc++) {
            cno = parseInt(cNodes[cnc].getAttribute('offset'));
            if (cno >= selection_start && cno <= selection_end) {
                $(cNodes[cnc]).removeClass("parser_hex_cell_select");
            }
        }
        selection_start = -1;
        selection_end = -1;
    }

    function clearAllSelection() {
        selection_start = -1;
        selection_end = -1;
        var hexview = document.getElementById('parser_center_wrapper');
        cNodes = hexview.childNodes;
        for (var cnc = 0; cnc < cNodes.length; cnc++) {
            $(cNodes[cnc]).removeClass("parser_hex_cell_select");
        }
    }

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

    function process_file(all_hex) {
        var hexview = document.getElementById('parser_center_wrapper');
        var file_data = window.localStorage.getItem('parser_file_content');
        hexview.innerHTML = "";
        var bcnt = 0;

        for (bcnt = 0; bcnt < file_data.length; bcnt++) {
            var hvItem = hexViewByte(file_data[bcnt], bcnt, all_hex);
            hexview.appendChild(hvItem);
        }

        find_strings();
    }

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

    $("body").on('mouseout', 'div.parser_hex_cell', function(evt) {
        $(evt.target).removeClass("parser_hex_cell_mark");
    });

    $("#parser_source_file").change(function() {
        var file = this.files[0];
        var reader = new FileReader();

        reader.onload = function(evt) {
            window.localStorage.setItem('parser_file', file);
            window.localStorage.setItem('parser_file_content', evt.target.result);
            process_file(false);
        };

        reader.readAsBinaryString(file);
    });

});

